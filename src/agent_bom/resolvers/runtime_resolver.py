"""Runtime version resolvers using package manager CLI tools.

Runs ``pip list``, ``npm ls``, and ``go list`` to get actually-installed
versions, complementing static lockfile parsing.  Each resolver returns
a dict of {package_name: installed_version} and handles missing tools
gracefully (returns empty dict if the tool isn't available).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

#: Maximum time (seconds) to wait for a package manager subprocess.
_SUBPROCESS_TIMEOUT = 30


def resolve_pip_versions(
    python_path: str | None = None,
) -> dict[str, str]:
    """Get installed Python package versions via ``pip list --format=json``.

    Args:
        python_path: Path to a Python interpreter (e.g., ``.venv/bin/python``).
            If None, uses the ``pip`` on PATH.

    Returns:
        Dict mapping lowercase package names to installed versions.
        Empty dict if pip is not available or the command fails.
    """
    if python_path:
        cmd = [python_path, "-m", "pip", "list", "--format=json"]
    else:
        pip_path = shutil.which("pip") or shutil.which("pip3")
        if not pip_path:
            logger.debug("resolve_pip_versions: pip not found on PATH")
            return {}
        cmd = [pip_path, "list", "--format=json"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0:
            logger.debug("resolve_pip_versions: pip list failed (rc=%d): %s", result.returncode, result.stderr[:200])
            return {}

        packages = json.loads(result.stdout)
        return {pkg["name"].lower(): pkg["version"] for pkg in packages if "name" in pkg and "version" in pkg}

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        logger.debug("resolve_pip_versions: %s", exc)
        return {}


def resolve_npm_versions(
    directory: Path,
) -> dict[str, str]:
    """Get installed npm package versions via ``npm ls --json --all``.

    Args:
        directory: Project directory containing package.json.

    Returns:
        Dict mapping package names to installed versions.
        Empty dict if npm is not available or the command fails.
    """
    npm_path = shutil.which("npm")
    if not npm_path:
        logger.debug("resolve_npm_versions: npm not found on PATH")
        return {}

    if not (directory / "package.json").exists():
        return {}

    try:
        result = subprocess.run(
            [npm_path, "ls", "--json", "--all"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            cwd=str(directory),
        )
        # npm ls returns non-zero if there are missing/extraneous deps,
        # but still outputs valid JSON. Parse it regardless.
        if not result.stdout.strip():
            return {}

        data = json.loads(result.stdout)
        versions: dict[str, str] = {}
        _walk_npm_tree(data.get("dependencies", {}), versions)
        return versions

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        logger.debug("resolve_npm_versions: %s", exc)
        return {}


def _walk_npm_tree(deps: dict, versions: dict[str, str]) -> None:
    """Recursively walk npm dependency tree to collect all installed versions."""
    for name, info in deps.items():
        if isinstance(info, dict) and "version" in info:
            versions[name] = info["version"]
            # Recurse into nested dependencies
            _walk_npm_tree(info.get("dependencies", {}), versions)


def resolve_go_versions(
    directory: Path,
) -> dict[str, str]:
    """Get installed Go module versions via ``go list -m -json all``.

    Args:
        directory: Project directory containing go.mod.

    Returns:
        Dict mapping module paths to installed versions (without 'v' prefix).
        Empty dict if go is not available or the command fails.
    """
    go_path = shutil.which("go")
    if not go_path:
        logger.debug("resolve_go_versions: go not found on PATH")
        return {}

    if not (directory / "go.mod").exists():
        return {}

    try:
        result = subprocess.run(
            [go_path, "list", "-m", "-json", "all"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            cwd=str(directory),
        )
        if result.returncode != 0:
            logger.debug("resolve_go_versions: go list failed (rc=%d): %s", result.returncode, result.stderr[:200])
            return {}

        # go list -m -json outputs concatenated JSON objects (not an array)
        versions: dict[str, str] = {}
        decoder = json.JSONDecoder()
        text = result.stdout.strip()
        idx = 0
        while idx < len(text):
            try:
                obj, end = decoder.raw_decode(text, idx)
                if "Path" in obj and "Version" in obj:
                    ver = obj["Version"]
                    clean_ver = ver[1:] if ver.startswith("v") else ver
                    versions[obj["Path"]] = clean_ver
                idx = end
                # Skip whitespace between objects
                while idx < len(text) and text[idx] in " \t\n\r":
                    idx += 1
            except json.JSONDecodeError:
                break

        return versions

    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("resolve_go_versions: %s", exc)
        return {}
