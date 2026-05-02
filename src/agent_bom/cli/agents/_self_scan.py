"""Self-scan inventory construction for the scan command."""

from __future__ import annotations

import importlib.metadata as metadata


def _build_self_scan_inventory() -> dict[str, list[dict[str, object]]]:
    """Build a self-scan inventory of every package installed in the venv.

    Pre-#2197 the scan walked only `agent-bom`'s declared `requires` (top
    level deps from pyproject.toml). The audit caught this: a fresh venv
    install of `agent-bom` carries ~23 declared deps but ~66 actual
    distributions once transitive deps resolve. CVEs in transitive deps
    were therefore invisible to `--self-scan`. We now walk
    `importlib.metadata.distributions()` so the self-scan reflects the
    real attack surface.
    """
    pkgs: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for dist in metadata.distributions():
        name = (dist.metadata["Name"] or "").strip()
        version = (dist.version or "").strip()
        if not name or not version:
            continue
        # Skip agent-bom itself -- it's the running tool, not a dep.
        if name.lower() == "agent-bom":
            continue
        key = (name.lower(), version, "pypi")
        if key in seen:
            continue
        seen.add(key)
        pkgs.append({"name": name, "version": version, "ecosystem": "pypi"})

    pkgs.sort(key=lambda p: (p["name"].lower(), p["version"]))

    return {
        "agents": [
            {
                "name": "agent-bom",
                "agent_type": "custom",
                "source": "agent-bom --self-scan",
                "config_path": "self-scan://agent-bom",
                "mcp_servers": [
                    {
                        "name": "agent-bom-mcp-server",
                        "command": "agent-bom mcp server",
                        "transport": "stdio",
                        "packages": pkgs,
                    }
                ],
            }
        ]
    }
