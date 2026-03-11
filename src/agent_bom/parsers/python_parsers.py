"""Python ecosystem package parsers.

Parses poetry.lock, uv.lock, requirements.txt, Pipfile.lock,
pyproject.toml, conda environment.yml, and live pip environments.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path

from agent_bom.models import Package

logger = logging.getLogger(__name__)


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
