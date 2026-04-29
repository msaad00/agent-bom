"""Shared base types for inventory parser modules."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agent_bom.extensions import ExtensionCapabilities, RegistryEntry
from agent_bom.models import MCPServer, Package


@dataclass(frozen=True)
class InventoryParserRegistration(RegistryEntry):
    """Registry metadata for an inventory parser implementation."""

    parse_attr: str = "parse"
    manifest_names: tuple[str, ...] = ()


class InventoryParser(Protocol):
    """Protocol implemented by package inventory parser extensions."""

    name: str
    capabilities: ExtensionCapabilities
    manifest_names: Sequence[str]

    def parse(self, root: Path, server: MCPServer | None = None) -> list[Package]:
        """Parse packages from an inventory root."""
