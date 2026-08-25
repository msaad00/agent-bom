"""Python ecosystem package parsers.

Parses poetry.lock, uv.lock, requirements.txt, Pipfile.lock,
pyproject.toml, conda environment.yml, and live pip environments.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from collections import Counter, defaultdict, deque
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.package_utils import normalize_package_name
from agent_bom.parsers.file_limits import read_json_limited, read_text_limited
from agent_bom.version_utils import strip_pip_extras

logger = logging.getLogger(__name__)

# PEP 508 direct-URL git reference (``flask @ git+https://…/flask.git@<sha>``)
# and the legacy ``git+https://…#egg=name`` form.
_GIT_DIRECT_URL_RE = re.compile(r"^(?P<name>[a-zA-Z0-9_.-]+)\s*@\s*(?P<url>\S+)$")
_GIT_EGG_RE = re.compile(r"[#&]egg=(?P<name>[a-zA-Z0-9_.-]+)")

_GIT_REF_FLOATING_REASON = (
    "declared as a git URL/SHA reference — a pinned git ref is not a released "
    "version, so any reported version is resolved from the installed host "
    "package, not the pinned ref"
)


#: Operators that pin an exact installed version. Everything else (``>=``,
#: ``<``, ``~=``, ``!=`` or a ``==x.*`` wildcard) is a range/constraint and does
#: not identify the installed version.
_EXACT_OPERATORS = {"==", "==="}


def _looks_like_git_requirement(url: str) -> bool:
    lowered = url.lower()
    return lowered.startswith(("git+", "git@", "git://")) or "git+" in lowered


def _with_manifest_location(package: Package, path: Path, line: int) -> Package:
    """Attach the declaration location used by machine-readable outputs."""
    package.version_evidence.append(
        {
            "type": "manifest",
            "source_file": str(path),
            "line": line,
        }
    )
    return package


def _requirement_package(name: str, operator: str, version: str, *, is_direct: bool) -> Package:
    """Build a Package for a ``name<op>version`` declaration line.

    An exact ``==`` pin is reported as the installed version. A range/inequality
    (``>=``/``<``/``~=``/``!=`` or a ``==x.*`` wildcard) does NOT identify an
    installed version — the named bound is a constraint the resolved version may
    even exclude (``<2.3`` excludes 2.3). Emitting ``pkg@<bound>`` as an exact pin
    is a fabricated fact, so a range is recorded as a floating declaration
    reference with lowered confidence instead. Packages come from a declaration
    manifest (no runtime/import proof), so reachability is ``declaration_only``.
    """
    if operator in _EXACT_OPERATORS and "*" not in version:
        return Package(
            name=name,
            version=version,
            ecosystem="pypi",
            purl=f"pkg:pypi/{name}@{version}",
            is_direct=is_direct,
            reachability_evidence="declaration_only",
        )
    return Package(
        name=name,
        version="unknown",
        ecosystem="pypi",
        is_direct=is_direct,
        declared_version=f"{operator}{version}",
        floating_reference=True,
        floating_reference_reason=(
            f"declared as a version constraint ({operator}{version}), not an exact "
            "pin — the installed version is unknown and may differ from the bound"
        ),
        version_confidence="low",
        reachability_evidence="declaration_only",
    )


def _git_reference_package(line: str, *, is_direct: bool = True) -> Package | None:
    """Return a Package for a git-URL requirement line, or None if not one.

    A git reference resolves (at scan time) to whatever the host environment has
    installed, which is *not* an exact match to the pinned ref. Mark it
    ``floating_reference`` with lowered confidence so downstream matching does not
    treat the host-env coincidence as an exact pin.
    """
    direct = _GIT_DIRECT_URL_RE.match(line)
    if direct and _looks_like_git_requirement(direct.group("url")):
        name, url = direct.group("name"), direct.group("url")
    elif _looks_like_git_requirement(line):
        egg = _GIT_EGG_RE.search(line)
        if not egg:
            return None
        name, url = egg.group("name"), line.split()[0]
    else:
        return None
    return Package(
        name=name,
        version="unknown",
        ecosystem="pypi",
        is_direct=is_direct,
        declared_version=url,
        floating_reference=True,
        floating_reference_reason=_GIT_REF_FLOATING_REASON,
        version_confidence="low",
        reachability_evidence="declaration_only",
    )


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

        data = tomllib.loads(read_text_limited(lock_file))
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
        record_manifest_parse_warning(
            ecosystem="pypi",
            path=str(lock_file),
            detail=f"poetry.lock failed to parse ({exc}); Python dependencies were not scanned",
        )

    return packages


def parse_uv_lock(directory: Path) -> list[Package]:
    """Parse packages from uv.lock (TOML format, uv package manager).

    uv.lock uses a ``[[package]]`` array similar to poetry.lock. Direct
    dependencies come from ``pyproject.toml``; resolved ``dependencies``
    entries preserve the runtime parent graph so downstream reachability can
    follow a proven lockfile edge without treating every declaration as live.
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

        data = tomllib.loads(read_text_limited(lock_file))
        # Collect direct dep names from pyproject.toml if available
        direct_names: set[str] = set()
        pyproject = directory / "pyproject.toml"
        if pyproject.exists():
            try:
                proj = tomllib.loads(read_text_limited(pyproject))
                for dep_str in proj.get("project", {}).get("dependencies", []):
                    m = re.match(r"^([a-zA-Z0-9_.-]+)", dep_str)
                    if m:
                        direct_names.add(normalize_package_name(m.group(1), "pypi"))
            except (OSError, tomllib.TOMLDecodeError, KeyError) as exc:
                logger.debug("Could not parse pyproject.toml for direct deps: %s", exc)

        package_rows = [pkg for pkg in data.get("package", []) if isinstance(pkg, dict)]
        names = [normalize_package_name(str(pkg.get("name", "")), "pypi") for pkg in package_rows]
        name_counts = Counter(names)
        unique_names = {name for name, count in name_counts.items() if name and count == 1}
        children: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for pkg in package_rows:
            parent = normalize_package_name(str(pkg.get("name", "")), "pypi")
            if parent not in unique_names:
                continue
            for dependency in pkg.get("dependencies", []):
                if isinstance(dependency, str):
                    child = normalize_package_name(dependency, "pypi")
                    scope = "runtime"
                elif isinstance(dependency, dict):
                    child = normalize_package_name(str(dependency.get("name", "")), "pypi")
                    scope = "conditional" if dependency.get("marker") else "runtime"
                else:
                    continue
                if child in unique_names:
                    children[parent].append((child, scope))

        # Select one deterministic shortest runtime introducing path for the
        # Package model's single parent field. Ambiguous versions are omitted
        # above rather than guessed.
        parent_by_name: dict[str, str] = {}
        depth_by_name: dict[str, int] = {name: 0 for name in direct_names if name in unique_names}
        queue = deque(sorted(depth_by_name))
        while queue:
            parent = queue.popleft()
            for child, scope in sorted(children.get(parent, [])):
                if scope != "runtime" or child in depth_by_name:
                    continue
                parent_by_name[child] = parent
                depth_by_name[child] = depth_by_name[parent] + 1
                queue.append(child)

        for pkg in package_rows:
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown")
            if not name:
                continue
            normalized_name = normalize_package_name(str(name), "pypi")
            is_direct = normalized_name in direct_names if direct_names else False
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    purl=f"pkg:pypi/{name}@{version}",
                    is_direct=is_direct,
                    parent_package=parent_by_name.get(normalized_name),
                    dependency_depth=depth_by_name.get(normalized_name, 0 if is_direct else 0),
                    dependency_scope="runtime" if is_direct or normalized_name in parent_by_name else "unknown",
                    reachability_evidence="lockfile",
                )
            )
    except Exception as exc:
        logger.debug("Failed to parse uv.lock at %s: %s", lock_file, exc)
        record_manifest_parse_warning(
            ecosystem="pypi",
            path=str(lock_file),
            detail=f"uv.lock failed to parse ({exc}); Python dependencies were not scanned",
        )

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

        data = yaml.safe_load(read_text_limited(env_file)) or {}
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
        record_manifest_parse_warning(
            ecosystem="conda",
            path=str(env_file),
            detail=f"{env_file.name} could not be read or parsed; Conda dependencies were not scanned",
        )

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
        malformed_requirements = False
        try:
            for line_number, raw_line in enumerate(read_text_limited(req_file).splitlines(), start=1):
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
                # Git URL/SHA reference (``flask @ git+…@<sha>``): version can't be
                # pinned from the ref, so flag it floating rather than dropping it.
                git_pkg = _git_reference_package(line, is_direct=True)
                if git_pkg is not None:
                    packages.append(_with_manifest_location(git_pkg, req_file, line_number))
                    continue
                # Parse name==version, name>=version, etc.
                match = re.match(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", line)
                if match:
                    raw_name, operator, version = match.groups()
                    name, _ = strip_pip_extras(raw_name)
                    packages.append(
                        _with_manifest_location(
                            _requirement_package(name, operator, version, is_direct=True),
                            req_file,
                            line_number,
                        )
                    )
                else:
                    # Just a name, no version
                    name_match = re.fullmatch(r"([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)(?:\s*;.*)?", line)
                    if name_match:
                        name, _ = strip_pip_extras(name_match.group(1))
                        packages.append(
                            _with_manifest_location(
                                Package(
                                    name=name,
                                    version="unknown",
                                    ecosystem="pypi",
                                    is_direct=True,
                                    reachability_evidence="declaration_only",
                                ),
                                req_file,
                                line_number,
                            )
                        )
                    else:
                        malformed_requirements = True
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed to read requirements.txt in %s: %s", directory, exc)
            record_manifest_parse_warning(
                ecosystem="pypi",
                path=str(req_file),
                detail="requirements.txt could not be read; Python dependencies were not scanned",
            )
        else:
            if malformed_requirements:
                record_manifest_parse_warning(
                    ecosystem="pypi",
                    path=str(req_file),
                    detail="requirements.txt contains malformed or truncated entries; Python dependency coverage is partial",
                )

    # Try Pipfile.lock
    pipfile_lock = directory / "Pipfile.lock"
    if pipfile_lock.exists() and not packages:
        try:
            lock_data = read_json_limited(pipfile_lock)
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
        except (json.JSONDecodeError, KeyError, OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed to parse Pipfile.lock in %s: %s", directory, exc)
            record_manifest_parse_warning(
                ecosystem="pypi",
                path=str(pipfile_lock),
                detail="Pipfile.lock could not be read or parsed; Python dependencies were not scanned",
            )

    # Try pyproject.toml
    pyproject = directory / "pyproject.toml"
    if pyproject.exists() and not packages:
        try:
            import toml

            proj_data = toml.loads(read_text_limited(pyproject))
            deps = proj_data.get("project", {}).get("dependencies", [])
            if not deps:
                poetry_deps = proj_data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                deps = []
                for raw_name, raw_spec in poetry_deps.items():
                    if str(raw_name).lower() == "python":
                        continue
                    if isinstance(raw_spec, dict):
                        raw_spec = raw_spec.get("version", "*")
                    spec = str(raw_spec or "*")
                    deps.append(f"{raw_name}{spec}")
            for dep in deps:
                match = re.match(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", dep)
                if match:
                    raw_name, operator, version = match.groups()
                    name, _ = strip_pip_extras(raw_name)
                    packages.append(_requirement_package(name, operator, version, is_direct=True))
                else:
                    bare = re.match(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)", dep)
                    if bare:
                        name, _ = strip_pip_extras(bare.group(1))
                        packages.append(
                            Package(
                                name=name,
                                version="unknown",
                                ecosystem="pypi",
                                is_direct=True,
                                reachability_evidence="declaration_only",
                            )
                        )
        except Exception as e:
            logger.debug(f"Failed to parse pyproject.toml at {pyproject}: {e}")
            record_manifest_parse_warning(
                ecosystem="pypi",
                path=str(pyproject),
                detail=f"pyproject.toml failed to parse ({e}); Python dependencies were not scanned",
            )

    return packages


def _parse_requirements_lines(lines: list[str], is_direct: bool = True) -> list[Package]:
    """Parse package entries from requirements-style text lines.

    Shared helper used by ``parse_pip_compile_inputs`` for both ``.in``
    source files and ``constraints.txt`` files.  Handles pinned (``==``),
    ranged (``>=``, ``~=``, etc.), and bare name lines.  Comment lines and
    option flags are silently skipped.
    """
    packages: list[Package] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", line)
        if m:
            raw_name, operator, req_version = m.groups()
            req_name, _ = strip_pip_extras(raw_name)
            packages.append(_requirement_package(req_name, operator, req_version, is_direct=is_direct))
        else:
            bare = re.match(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)", line)
            if bare:
                req_name, _ = strip_pip_extras(bare.group(1))
                packages.append(
                    Package(
                        name=req_name,
                        version="unknown",
                        ecosystem="pypi",
                        is_direct=is_direct,
                        reachability_evidence="declaration_only",
                    )
                )
    return packages


def parse_pip_compile_inputs(directory: Path) -> list[Package]:
    """Parse pip-compile source (``.in``) and constraints files.

    pip-tools compiles abstract ``requirements.in`` files into pinned
    ``requirements.txt`` lockfiles.  This parser handles the following cases:

    * If both ``requirements.in`` and ``requirements.txt`` already exist the
      compiled ``.txt`` is preferred (handled by ``parse_pip_packages``).
      This function only runs when ``.in`` files exist *without* a
      corresponding compiled ``.txt`` to avoid double-counting.
    * ``constraints.txt`` — version constraints rather than direct installs;
      marked ``is_direct=False``.

    Candidate ``.in`` file names::

        requirements.in, requirements-dev.in, requirements-prod.in,
        base.in, dev.in, prod.in

    Returns an empty list when no ``.in`` or ``constraints.txt`` files exist.
    """
    in_candidates = [
        "requirements.in",
        "requirements-dev.in",
        "requirements-prod.in",
        "base.in",
        "dev.in",
        "prod.in",
    ]

    packages: list[Package] = []

    for in_name in in_candidates:
        in_file = directory / in_name
        if not in_file.exists():
            continue
        # If a compiled .txt counterpart exists, skip: parse_pip_packages handles it.
        compiled_name = in_name.replace(".in", ".txt")
        if (directory / compiled_name).exists():
            logger.debug(
                "Skipping %s — compiled %s exists and takes precedence",
                in_file,
                compiled_name,
            )
            continue
        try:
            in_lines = in_file.read_text(encoding="utf-8").splitlines()
            packages.extend(_parse_requirements_lines(in_lines, is_direct=True))
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed to read %s: %s", in_file, exc)
            record_manifest_parse_warning(
                ecosystem="pypi",
                path=str(in_file),
                detail=f"{in_file.name} could not be read; pip-compile dependencies were not scanned",
            )

    # constraints.txt — version pins for transitive deps; not direct installs
    constraints_file = directory / "constraints.txt"
    if constraints_file.exists():
        try:
            c_lines = constraints_file.read_text(encoding="utf-8").splitlines()
            packages.extend(_parse_requirements_lines(c_lines, is_direct=False))
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed to read %s: %s", constraints_file, exc)
            record_manifest_parse_warning(
                ecosystem="pypi",
                path=str(constraints_file),
                detail="constraints.txt could not be read; constrained Python dependencies were not scanned",
            )

    return packages


def parse_pip_environment(python_exec: str | None = None) -> list[Package]:
    """Scan an installed Python environment for installed packages.

    Useful when there is no lock file (e.g. bare virtualenv, conda env,
    system Python) and you want to audit what's actually installed.

    Args:
        python_exec: Path to the Python interpreter whose environment to scan.
            Defaults to ``sys.executable`` (the currently-running Python).

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="pypi"``.  Prefers ``pip list --format=json`` and falls
        back to ``importlib.metadata`` for environments that intentionally do
        not install the ``pip`` package.
    """
    import sys as _sys

    def _packages_from_rows(rows: list[dict[str, str]]) -> list[Package]:
        packages: list[Package] = []
        for entry in rows:
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
        try:
            fallback = subprocess.run(
                [
                    exe,
                    "-c",
                    (
                        "import importlib.metadata as m, json; "
                        "print(json.dumps(["
                        "{'name': d.metadata.get('Name') or d.metadata.get('name') or '', "
                        "'version': d.version} "
                        "for d in m.distributions()]))"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.debug("parse_pip_environment: metadata fallback failed (%s)", exc)
            return []
        if fallback.returncode != 0:
            logger.debug(
                "parse_pip_environment: metadata fallback failed: %s",
                fallback.stderr[:200],
            )
            return []
        try:
            raw = json.loads(fallback.stdout)
        except json.JSONDecodeError:
            return []
        return _packages_from_rows(raw)

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    return _packages_from_rows(raw)
