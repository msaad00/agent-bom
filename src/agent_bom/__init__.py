"""agent-bom: Security scanner for AI infrastructure — from agent to runtime."""

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("agent-bom")
except PackageNotFoundError:
    __version__ = "0.76.4"

# Cross-check against pyproject.toml for dev installs where the editable
# install metadata may be stale (i.e. version bumped but not re-installed).
_pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
if _pyproject.exists():
    try:
        _m = re.search(r'version\s*=\s*"([^"]+)"', _pyproject.read_text())
        if _m and _m.group(1) != __version__:
            __version__ = _m.group(1)
    except Exception:
        pass  # Never block import due to pyproject read failure
