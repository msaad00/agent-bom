"""Auto-configure the agent-bom security proxy for discovered MCP servers.

For every STDIO MCPServer with a known command, generates a proxy-wrapped
configuration entry that the MCP client (Claude Desktop, Cursor, etc.) can use
in place of the original entry.

The proxied entry replaces:

    "command": "npx",
    "args": ["@modelcontextprotocol/server-fs", "/tmp"]

with:

    "command": "agent-bom",
    "args": ["proxy", "--", "npx", "@modelcontextprotocol/server-fs", "/tmp"]

Optionally enriches the proxy args with --log, --policy, --detect-credentials,
and --block-undeclared flags.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agent_bom.models import Agent, TransportType

logger = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    """A proxy-wrapped configuration for one MCP server."""

    server_name: str
    """Human-readable server name (from MCPServer.name)."""

    config_path: str
    """Source config file that declared this server."""

    original_command: str
    """Original command before proxying."""

    original_args: list[str]
    """Original args before proxying."""

    proxied_command: str = "agent-bom"
    """Replacement command (always agent-bom)."""

    proxied_args: list[str] = field(default_factory=list)
    """Replacement args — wraps original command with proxy flags."""

    proxy_flags: list[str] = field(default_factory=list)
    """Proxy flags injected (--log, --policy, etc.)."""

    def as_json_entry(self) -> dict:
        """Return a JSON-serialisable config entry for the MCP client."""
        entry: dict = {"command": self.proxied_command, "args": self.proxied_args}
        if hasattr(self, "_env") and self._env:
            entry["env"] = self._env
        return entry


def auto_configure_proxies(
    agents: list[Agent],
    policy_path: Optional[str] = None,
    log_dir: Optional[str] = None,
    secure_defaults: bool = True,
    detect_credentials: bool = False,
    block_undeclared: bool = False,
) -> list[ProxyConfig]:
    """Generate proxy-wrapped configs for all eligible STDIO MCP servers.

    Only STDIO servers with a non-empty command are eligible.
    SSE/HTTP servers are skipped because they communicate over the network and
    don't go through a subprocess stdio pipe.

    Args:
        agents: Discovered Agent objects (from ``discover_all()``).
        policy_path: Optional policy JSON file to pass to each proxy instance.
        log_dir: Directory for per-server audit logs.  Each server gets a file
            named ``<server_name_slug>.jsonl`` inside this directory.
        secure_defaults: When True, inject the recommended protective flags
            (currently ``--detect-credentials`` and ``--block-undeclared``)
            even if they are not explicitly requested by the caller.
        detect_credentials: Pass ``--detect-credentials`` to each proxy.
        block_undeclared: Pass ``--block-undeclared`` to each proxy.

    Returns:
        List of ProxyConfig objects, one per eligible server.
    """
    results: list[ProxyConfig] = []

    for agent in agents:
        for server in agent.mcp_servers:
            if server.transport != TransportType.STDIO:
                continue
            if not server.command:
                continue

            proxy_flags: list[str] = []

            if policy_path:
                proxy_flags += ["--policy", policy_path]

            if log_dir:
                slug = re.sub(r"[^a-zA-Z0-9_-]", "_", server.name)[:64]
                log_file = str(Path(log_dir) / f"{slug}.jsonl")
                proxy_flags += ["--log", log_file]

            if secure_defaults or detect_credentials:
                proxy_flags.append("--detect-credentials")

            if secure_defaults or block_undeclared:
                proxy_flags.append("--block-undeclared")

            proxied_args = [*proxy_flags, "--", server.command, *server.args]

            config = ProxyConfig(
                server_name=server.name,
                config_path=server.config_path or agent.config_path or "unknown",
                original_command=server.command,
                original_args=list(server.args),
                proxied_args=proxied_args,
                proxy_flags=proxy_flags,
            )
            results.append(config)

    return results


def apply_proxy_configs(
    configs: list[ProxyConfig],
    dry_run: bool = True,
) -> int:
    """Write proxy-wrapped entries back to their source config files.

    Only JSON config files are supported (claude_desktop_config.json,
    mcp.json, etc.).  The function patches the ``mcpServers`` or ``servers``
    key in-place — all other keys are preserved.

    Args:
        configs: ProxyConfig objects from ``auto_configure_proxies()``.
        dry_run: If True, no files are modified (preview only).

    Returns:
        Number of config files actually modified (0 in dry_run mode).
    """
    # Group configs by source file
    by_file: dict[str, list[ProxyConfig]] = {}
    for cfg in configs:
        key = cfg.config_path
        by_file.setdefault(key, []).append(cfg)

    modified = 0

    for config_path, file_configs in by_file.items():
        path = Path(config_path)
        if not path.exists() or path.suffix.lower() != ".json":
            logger.debug("Skipping non-JSON or missing config: %s", config_path)
            continue

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Cannot read %s: %s", config_path, exc)
            continue

        # Locate the server map (mcpServers or servers)
        servers_key = "mcpServers" if "mcpServers" in data else "servers" if "servers" in data else None
        if servers_key is None:
            logger.debug("No mcpServers/servers key in %s", config_path)
            continue

        changed = False
        for cfg in file_configs:
            # Look for the server by matching its original command AND args
            server_map = data[servers_key]
            for entry_key, entry_val in server_map.items():
                if not isinstance(entry_val, dict):
                    continue
                if entry_val.get("command") == cfg.original_command and entry_val.get("args", []) == cfg.original_args:
                    if dry_run:
                        logger.info("[dry-run] Would patch %s/%s in %s", servers_key, entry_key, config_path)
                    else:
                        server_map[entry_key] = cfg.as_json_entry()
                        logger.info("Patched %s/%s in %s", servers_key, entry_key, config_path)
                    changed = True
                    break

        if changed and not dry_run:
            try:
                # Preserve original file permissions
                try:
                    orig_mode = path.stat().st_mode
                except OSError:
                    orig_mode = stat.S_IRUSR | stat.S_IWUSR  # 0o600 default

                # Atomic write: temp file + rename to prevent corruption
                fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp", prefix=".agent-bom-")
                fd_closed = False
                try:
                    os.write(fd, json.dumps(data, indent=2).encode("utf-8"))
                    os.close(fd)
                    fd_closed = True
                    os.chmod(tmp_path, orig_mode & 0o777)
                    os.replace(tmp_path, str(path))
                except BaseException:
                    if not fd_closed:
                        os.close(fd)
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise
                modified += 1
            except OSError as exc:
                logger.warning("Cannot write %s: %s", config_path, exc)

    return modified
