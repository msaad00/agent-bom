"""Parse package dependencies from MCP server directories."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

from agent_bom.models import MCPServer, Package

# Path to bundled MCP registry (parsers/ is a subdir of agent_bom/)
_REGISTRY_PATH = Path(__file__).parent.parent / "mcp_registry.json"


def _npm_purl(name: str, version: str) -> str:
    """Build a PURL for an npm package, correctly encoding scoped names.

    Per the PURL spec, ``@scope/name`` becomes ``pkg:npm/%40scope/name@version``.
    """
    from urllib.parse import quote

    if name.startswith("@"):
        # Encode the '@' in the scope per PURL spec
        scope, _, pkg_name = name[1:].partition("/")
        return f"pkg:npm/{quote('@' + scope, safe='')}/{pkg_name}@{version}"
    return f"pkg:npm/{name}@{version}"


_registry_cache: Optional[dict] = None


def _load_registry() -> dict:
    """Load the bundled MCP server registry (cached)."""
    global _registry_cache
    if _registry_cache is None:
        try:
            _registry_cache = json.loads(_REGISTRY_PATH.read_text()).get("servers", {})
        except Exception:
            _registry_cache = {}
    return _registry_cache


def _extract_version_from_args(args: list[str]) -> str | None:
    """Try to extract a pinned version from server command args.

    Detects patterns like @1.2.3, ==1.2.3, or version flags.
    """
    for arg in args:
        if arg.startswith("-"):
            continue
        # npm-style: @scope/package@1.2.3
        m = re.search(r"@(\d+\.\d+[\w.-]*)\s*$", arg)
        if m:
            return m.group(1)
        # pip-style: package==1.2.3
        m = re.search(r"==(\d+\.\d+[\w.-]*)$", arg)
        if m:
            return m.group(1)
    return None


def lookup_mcp_registry(server: MCPServer) -> list[Package]:
    """Look up an MCP server's packages using the bundled registry.

    Matches on:
    1. Exact npm package name in args (e.g. @modelcontextprotocol/server-filesystem)
    2. command_patterns substring match against server name or args

    Preserves the registry's latest_version in registry_version for drift
    comparison, and tries to detect the actual installed version from args.
    If no installed version is detectable, version is set to "latest" so the
    resolver can query npm/PyPI for the real current version.
    """
    registry = _load_registry()
    if not registry:
        return []

    candidates: list[str] = [server.name] + server.args

    for pkg_name, entry in registry.items():
        patterns = entry.get("command_patterns", [pkg_name])
        for candidate in candidates:
            for pattern in patterns:
                if pattern in candidate or candidate in pkg_name:
                    ecosystem = entry.get("ecosystem", "npm")
                    registry_version = entry.get("latest_version", "latest")
                    risk_level = entry.get("risk_level")
                    verified = entry.get("verified", False)

                    # Try to detect actual installed version from args
                    detected_version = _extract_version_from_args(server.args)
                    if detected_version:
                        version = detected_version
                        version_source = "detected"
                    else:
                        # Set to "latest" so resolver queries npm/PyPI
                        # for the actual current version
                        version = "latest"
                        version_source = "registry_fallback"

                    # Log warnings for unverified or high-risk servers
                    if not verified:
                        logger.info(
                            "Registry: %s is UNVERIFIED — review source before trusting",
                            entry["package"],
                        )
                    if risk_level == "high":
                        logger.info(
                            "Registry: %s has HIGH risk level — has privileged tool access",
                            entry["package"],
                        )

                    return [
                        Package(
                            name=entry["package"],
                            version=version,
                            ecosystem=ecosystem,
                            purl=f"pkg:{ecosystem}/{entry['package']}@{version}",
                            is_direct=True,
                            resolved_from_registry=True,
                            registry_version=registry_version,
                            version_source=version_source,
                        )
                    ]
    return []


def get_registry_entry(server: MCPServer) -> dict | None:
    """Return the full registry entry for an MCP server, or None."""
    registry = _load_registry()
    if not registry:
        return None

    candidates: list[str] = [server.name] + server.args

    for pkg_name, entry in registry.items():
        patterns = entry.get("command_patterns", [pkg_name])
        for candidate in candidates:
            for pattern in patterns:
                if pattern in candidate or candidate in pkg_name:
                    return entry
    return None


console = Console(stderr=True)
logger = logging.getLogger(__name__)


def find_server_directory(server: MCPServer) -> Optional[Path]:
    """Attempt to find the MCP server's source directory."""
    # Check working_dir first
    if server.working_dir and os.path.isdir(server.working_dir):
        return Path(server.working_dir)

    # Check args for paths
    for arg in server.args:
        if os.path.isdir(arg):
            return Path(arg)
        # Check if arg is a file, use its parent
        if os.path.isfile(arg):
            return Path(arg).parent

    # For npx/npm commands, check if there's a package reference
    if server.command in ("npx", "npm"):
        # npx packages are in node_modules or global cache
        for arg in server.args:
            if not arg.startswith("-"):
                # This is likely the package name
                return None  # Can't resolve npx packages to local dirs

    # For uvx/uv commands
    if server.command in ("uvx", "uv"):
        return None  # Virtual env packages

    # For direct python/node commands, check the script path
    if server.command in ("python", "python3", "node"):
        for arg in server.args:
            if not arg.startswith("-") and os.path.isfile(arg):
                return Path(arg).parent

    return None


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


def parse_poetry_lock(directory: Path) -> list[Package]:
    """Parse packages from poetry.lock (TOML format).

    poetry.lock lists every resolved package with exact versions and marks
    which are direct dependencies via the [extras] table and the package
    categories.  We mark ``is_direct=True`` for packages in the ``main``
    group (default) and set it False for dev-only packages.
    """
    lock_file = directory / "poetry.lock"
    if not lock_file.exists():
        return []

    packages: list[Package] = []
    try:
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef,no-reattr,import-not-found]
            except ImportError:
                import toml as tomllib  # type: ignore[no-redef,no-reattr,import-not-found,import-untyped]

        data = tomllib.loads(lock_file.read_text())
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown")
            category = pkg.get("category", "main")  # "main" or "dev"
            if not name:
                continue
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    purl=f"pkg:pypi/{name}@{version}",
                    is_direct=(category == "main"),
                )
            )
    except Exception as exc:
        logger.debug("Failed to parse poetry.lock at %s: %s", lock_file, exc)

    return packages


def parse_uv_lock(directory: Path) -> list[Package]:
    """Parse packages from uv.lock (TOML format, uv package manager).

    uv.lock uses a [[package]] array similar to poetry.lock.  Direct
    dependencies have a ``[package.metadata]`` table; all entries have
    ``name`` and ``version``.  We treat every entry as a resolved dep and
    mark is_direct=False (uv flattens the graph; direct vs transitive
    distinction requires reading pyproject.toml alongside the lock file).
    """
    lock_file = directory / "uv.lock"
    if not lock_file.exists():
        return []

    packages: list[Package] = []
    try:
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef,no-reattr,import-not-found]
            except ImportError:
                import toml as tomllib  # type: ignore[no-redef,no-reattr,import-not-found,import-untyped]

        data = tomllib.loads(lock_file.read_text())
        # Collect direct dep names from pyproject.toml if available
        direct_names: set[str] = set()
        pyproject = directory / "pyproject.toml"
        if pyproject.exists():
            try:
                proj = tomllib.loads(pyproject.read_text())
                for dep_str in proj.get("project", {}).get("dependencies", []):
                    m = re.match(r"^([a-zA-Z0-9_.-]+)", dep_str)
                    if m:
                        direct_names.add(m.group(1).lower())
            except (OSError, tomllib.TOMLDecodeError, KeyError) as exc:
                logger.debug("Could not parse pyproject.toml for direct deps: %s", exc)

        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown")
            if not name:
                continue
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    purl=f"pkg:pypi/{name}@{version}",
                    is_direct=(name.lower() in direct_names) if direct_names else False,
                )
            )
    except Exception as exc:
        logger.debug("Failed to parse uv.lock at %s: %s", lock_file, exc)

    return packages


def parse_conda_environment(directory: Path) -> list[Package]:
    """Parse packages from conda environment.yml or environment.yaml.

    Supports both pip-installed packages (listed under ``pip:`` key) and
    conda packages (listed under ``dependencies``).  Conda packages with
    pinned versions (``name=version``) are extracted; unpinned ones are
    skipped as they have no version to scan.
    """
    for name in ("environment.yml", "environment.yaml"):
        env_file = directory / name
        if env_file.exists():
            break
    else:
        return []

    packages: list[Package] = []
    try:
        try:
            import yaml  # type: ignore[import-untyped]  # PyYAML
        except ImportError:
            logger.debug("PyYAML not installed; skipping conda environment.yml parsing")
            return []

        data = yaml.safe_load(env_file.read_text()) or {}
        for dep in data.get("dependencies", []):
            if isinstance(dep, str):
                # conda package: "name=version=build" or "name=version" or "name"
                parts = dep.split("=")
                pkg_name = parts[0].strip()
                pkg_version = parts[1].strip() if len(parts) >= 2 else "unknown"
                if pkg_name and pkg_version != "unknown":
                    packages.append(
                        Package(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="conda",
                            purl=f"pkg:conda/{pkg_name}@{pkg_version}",
                            is_direct=True,
                        )
                    )
            elif isinstance(dep, dict) and "pip" in dep:
                # pip sub-list: ["requests==2.28.0", ...]
                for pip_dep in dep.get("pip", []):
                    m = re.match(r"^([a-zA-Z0-9_.-]+)\s*[=<>!~]+\s*([a-zA-Z0-9_.*+-]+)", pip_dep)
                    if m:
                        packages.append(
                            Package(
                                name=m.group(1),
                                version=m.group(2),
                                ecosystem="pypi",
                                purl=f"pkg:pypi/{m.group(1)}@{m.group(2)}",
                                is_direct=True,
                            )
                        )
    except Exception as exc:
        logger.debug("Failed to parse conda environment at %s: %s", env_file, exc)

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


def parse_pip_packages(directory: Path) -> list[Package]:
    """Parse packages from requirements.txt, Pipfile.lock, pyproject.toml,
    poetry.lock, or uv.lock.

    Priority order (first match wins for Python projects):
    1. poetry.lock  — exact resolved versions, most accurate
    2. uv.lock      — exact resolved versions (uv package manager)
    3. requirements.txt — pinned or ranged versions
    4. Pipfile.lock — Pipenv resolved versions
    5. pyproject.toml — declared deps (no resolved versions)
    """
    # Poetry (most accurate — full resolved lock)
    poetry_pkgs = parse_poetry_lock(directory)
    if poetry_pkgs:
        return poetry_pkgs

    # uv lock
    uv_pkgs = parse_uv_lock(directory)
    if uv_pkgs:
        return uv_pkgs

    packages = []

    # Try requirements.txt
    req_file = directory / "requirements.txt"
    if req_file.exists():
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parse name==version, name>=version, etc.
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", line)
            if match:
                name, _, version = match.groups()
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )
            else:
                # Just a name, no version
                name_match = re.match(r"^([a-zA-Z0-9_.-]+)", line)
                if name_match:
                    packages.append(
                        Package(
                            name=name_match.group(1),
                            version="unknown",
                            ecosystem="pypi",
                            is_direct=True,
                        )
                    )

    # Try Pipfile.lock
    pipfile_lock = directory / "Pipfile.lock"
    if pipfile_lock.exists() and not packages:
        try:
            lock_data = json.loads(pipfile_lock.read_text())
            for section in ("default", "develop"):
                for name, info in lock_data.get(section, {}).items():
                    if isinstance(info, dict):
                        version = info.get("version", "").lstrip("=")
                        packages.append(
                            Package(
                                name=name,
                                version=version or "unknown",
                                ecosystem="pypi",
                                purl=f"pkg:pypi/{name}@{version}" if version else None,
                                is_direct=section == "default",
                            )
                        )
        except (json.JSONDecodeError, KeyError):
            pass

    # Try pyproject.toml
    pyproject = directory / "pyproject.toml"
    if pyproject.exists() and not packages:
        try:
            import toml

            proj_data = toml.loads(pyproject.read_text())
            deps = proj_data.get("project", {}).get("dependencies", [])
            for dep in deps:
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", dep)
                if match:
                    name, _, version = match.groups()
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            purl=f"pkg:pypi/{name}@{version}",
                            is_direct=True,
                        )
                    )
        except Exception as e:
            logger.debug(f"Failed to parse pyproject.toml at {pyproject}: {e}")

    return packages


def parse_pip_environment(python_exec: str | None = None) -> list[Package]:
    """Scan an installed Python environment via ``pip list --format=json``.

    Useful when there is no lock file (e.g. bare virtualenv, conda env,
    system Python) and you want to audit what's actually installed.

    Args:
        python_exec: Path to the Python interpreter whose environment to scan.
            Defaults to ``sys.executable`` (the currently-running Python).

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="pypi"``.  Returns an empty list if ``pip`` is not
        available in the target environment.
    """
    import sys as _sys

    exe = python_exec or _sys.executable
    try:
        result = subprocess.run(
            [exe, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.debug("parse_pip_environment: pip not available (%s)", exc)
        return []

    if result.returncode != 0:
        logger.debug("parse_pip_environment: pip list failed: %s", result.stderr[:200])
        return []

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    packages: list[Package] = []
    for entry in raw:
        name = entry.get("name", "")
        version = entry.get("version", "unknown")
        if name:
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    purl=f"pkg:pypi/{name.lower()}@{version}",
                    is_direct=True,
                )
            )

    return packages


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


def extract_packages(
    server: MCPServer,
    resolve_transitive: bool = False,
    max_depth: int = 3,
    smithery_token: str | None = None,
    mcp_registry: bool = False,
) -> list[Package]:
    """Extract all packages for an MCP server.

    Args:
        server: The MCP server to extract packages from
        resolve_transitive: If True, resolve transitive dependencies for npx/uvx packages
        max_depth: Maximum depth for transitive dependency resolution
        smithery_token: Optional Smithery API key for live registry fallback
        mcp_registry: If True, query the Official MCP Registry as a fallback
    """
    packages = []

    # Try npx/uvx command extraction first
    npx_packages = detect_npx_package(server)
    uvx_packages = detect_uvx_package(server)
    packages.extend(npx_packages)
    packages.extend(uvx_packages)

    # Try to find local directory and parse manifests
    server_dir = find_server_directory(server)
    if server_dir:
        packages.extend(parse_npm_packages(server_dir))
        packages.extend(parse_yarn_lock(server_dir))
        packages.extend(parse_pnpm_lock(server_dir))
        packages.extend(parse_pip_packages(server_dir))  # includes poetry.lock + uv.lock
        packages.extend(parse_conda_environment(server_dir))
        packages.extend(parse_go_packages(server_dir))
        packages.extend(parse_cargo_packages(server_dir))
        packages.extend(parse_maven_packages(server_dir))

    # If we only got npx/uvx packages (no local directory), resolve transitive deps
    if resolve_transitive and (npx_packages or uvx_packages) and not server_dir:
        console.print(f"  [cyan]→[/cyan] Resolving transitive dependencies for {server.name} (depth={max_depth})...")
        from agent_bom.transitive import resolve_transitive_dependencies_sync

        # Resolve transitive deps for npx/uvx packages only
        remote_packages = npx_packages + uvx_packages
        transitive_deps = resolve_transitive_dependencies_sync(remote_packages, max_depth)
        packages.extend(transitive_deps)

        if transitive_deps:
            console.print(f"  [green]✓[/green] Found {len(transitive_deps)} transitive dependencies")

    # Registry fallback: if we still have no packages, look up by server name/args
    if not packages:
        registry_packages = lookup_mcp_registry(server)
        if registry_packages:
            console.print(f"  [dim cyan]→ {server.name}: resolved from MCP registry ({registry_packages[0].name})[/dim cyan]")
            # Enrich server with permission profile from registry data
            entry = get_registry_entry(server)
            if entry:
                from agent_bom.permissions import build_permission_profile

                tool_names = entry.get("tools", [])
                cred_vars = entry.get("credential_env_vars", [])
                profile = build_permission_profile(
                    tools=tool_names,
                    credential_env_vars=cred_vars,
                    command=server.command,
                    args=server.args,
                )
                # Merge with discovery-time profile if present
                if server.permission_profile is not None:
                    profile.runs_as_root = profile.runs_as_root or server.permission_profile.runs_as_root
                    profile.shell_access = profile.shell_access or server.permission_profile.shell_access
                    profile.container_privileged = server.permission_profile.container_privileged
                    profile.capabilities = server.permission_profile.capabilities
                    profile.security_opt = server.permission_profile.security_opt
                server.permission_profile = profile
        packages.extend(registry_packages)

    # Official MCP Registry fallback: free API, no auth required
    if not packages and mcp_registry:
        try:
            from agent_bom.mcp_official_registry import official_registry_lookup_sync

            mcp_reg_packages = official_registry_lookup_sync(server)
            if mcp_reg_packages:
                console.print(f"  [dim blue]→ {server.name}: resolved from Official MCP Registry ({mcp_reg_packages[0].name})[/dim blue]")
            packages.extend(mcp_reg_packages)
        except Exception as exc:
            logger.debug("Official MCP Registry lookup failed for %s: %s", server.name, exc)

    # Smithery fallback: if local registry also missed, try Smithery API
    if not packages and smithery_token:
        try:
            from agent_bom.smithery import smithery_lookup_sync

            smithery_packages = smithery_lookup_sync(server, token=smithery_token)
            if smithery_packages:
                console.print(f"  [dim magenta]→ {server.name}: resolved from Smithery ({smithery_packages[0].name})[/dim magenta]")
            packages.extend(smithery_packages)
        except Exception as exc:
            logger.debug("Smithery lookup failed for %s: %s", server.name, exc)

    # Deduplicate
    seen = set()
    unique = []
    for pkg in packages:
        key = (pkg.name, pkg.version, pkg.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)

    return unique


# ── Project directory scanner ─────────────────────────────────────────────────

#: Package manifest file names that indicate a scannable directory.
_MANIFEST_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "environment.yml",
        "environment.yaml",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
    }
)

#: Directories to skip during recursive project scan.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "dist",
        "build",
        ".cache",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "target",  # Rust/Maven
        ".cargo",
    }
)


def _has_manifest(directory: Path) -> bool:
    """Return True if *directory* contains at least one package manifest."""
    return any((directory / name).exists() for name in _MANIFEST_FILES)


def scan_project_directory(
    root: Path,
    max_depth: int = 5,
) -> dict[Path, list[Package]]:
    """Recursively walk *root* for package manifests and parse all packages.

    Returns a mapping of ``{directory: [Package, ...]}`` for each directory
    that contains at least one supported manifest file.  Directories in
    ``_SKIP_DIRS`` and hidden directories (starting with ``.``) beyond the
    root are silently skipped.

    Args:
        root: Project root directory to scan.
        max_depth: Maximum directory depth to descend (default 5).

    Returns:
        Dict mapping each manifest-bearing directory to its parsed packages.
        Empty dict if no manifests are found.
    """
    root = Path(root).resolve()
    results: dict[Path, list[Package]] = {}

    def _walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return

        if _has_manifest(directory):
            pkgs: list[Package] = []
            pkgs.extend(parse_npm_packages(directory))
            pkgs.extend(parse_yarn_lock(directory))
            pkgs.extend(parse_pnpm_lock(directory))
            pkgs.extend(parse_pip_packages(directory))
            pkgs.extend(parse_conda_environment(directory))
            pkgs.extend(parse_go_packages(directory))
            pkgs.extend(parse_cargo_packages(directory))
            pkgs.extend(parse_maven_packages(directory))

            # Deduplicate within this directory
            seen: set[tuple] = set()
            unique: list[Package] = []
            for pkg in pkgs:
                key = (pkg.name, pkg.version, pkg.ecosystem)
                if key not in seen:
                    seen.add(key)
                    unique.append(pkg)

            if unique:
                results[directory] = unique

        # Recurse into subdirectories
        try:
            subdirs = [
                d for d in directory.iterdir() if d.is_dir() and d.name not in _SKIP_DIRS and not (d.name.startswith(".") and depth > 0)
            ]
        except PermissionError:
            return

        for subdir in sorted(subdirs):
            _walk(subdir, depth + 1)

    _walk(root, 0)
    return results
