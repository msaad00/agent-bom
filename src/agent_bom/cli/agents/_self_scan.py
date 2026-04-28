"""Self-scan inventory construction for the scan command."""

from __future__ import annotations

import importlib.metadata as metadata


def _build_self_scan_inventory() -> dict[str, list[dict[str, object]]]:
    """Build a deterministic self-scan inventory for the installed package."""
    pkgs: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    dist = metadata.distribution("agent-bom")
    for req_str in dist.requires or []:
        name = req_str.split(";")[0].split("[")[0].strip()
        for op in (">=", "<=", "==", "!=", "~=", ">", "<"):
            if op in name:
                name = name[: name.index(op)].strip()
                break
        if not name:
            continue
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
        key = (name.lower(), version, "pypi")
        if key in seen:
            continue
        seen.add(key)
        pkgs.append({"name": name, "version": version, "ecosystem": "pypi"})

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
                        "command": "agent-bom mcp-server",
                        "transport": "stdio",
                        "packages": pkgs,
                    }
                ],
            }
        ]
    }
