"""Indexes owned by one graph build; never shared between tenants or snapshots."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BuildIndexes:
    server_to_agents: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    pkg_key_to_servers: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    package_name_to_ids: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    server_name_to_ids: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    agent_name_to_ids: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    server_name_to_agent_servers: dict[str, dict[str, str]] = field(default_factory=lambda: defaultdict(dict))
    agent_to_server_ids: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    agent_config_path_to_id: dict[str, str] = field(default_factory=dict)
    server_to_tool_ids: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    package_id_to_servers: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    pending_exploitable_edges: list[tuple[str, str, str, dict[str, Any], str]] = field(default_factory=list)
