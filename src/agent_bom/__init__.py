"""agent-bom: Security scanner for AI supply chain and infrastructure — from agent to runtime."""

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    __version__ = version("agent-bom")
except PackageNotFoundError:
    __version__ = "0.108.4"

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

if TYPE_CHECKING:
    from agent_bom.client import AgentBomApiError, AgentBomClient
    from agent_bom.sdk import (
        AgentBomSDKError,
        DiffResult,
        InventoryResult,
        PackageCheckResult,
        async_check,
        check,
        diff,
        scan,
    )

__all__ = [
    "__version__",
    "AgentBomApiError",
    "AgentBomClient",
    "AgentBomSDKError",
    "DiffResult",
    "InventoryResult",
    "PackageCheckResult",
    "async_check",
    "check",
    "diff",
    "scan",
]

# The SDK imports the MCP server runtime (and through it the MCP framework),
# which dominates CLI cold start. Resolve the public API on first access
# (PEP 562) so ``import agent_bom`` and the CLI entry point stay light.
_LAZY_EXPORTS = {
    "AgentBomSDKError": "agent_bom.sdk",
    "DiffResult": "agent_bom.sdk",
    "InventoryResult": "agent_bom.sdk",
    "PackageCheckResult": "agent_bom.sdk",
    "async_check": "agent_bom.sdk",
    "check": "agent_bom.sdk",
    "diff": "agent_bom.sdk",
    "scan": "agent_bom.sdk",
    "AgentBomApiError": "agent_bom.client",
    "AgentBomClient": "agent_bom.client",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module 'agent_bom' has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
