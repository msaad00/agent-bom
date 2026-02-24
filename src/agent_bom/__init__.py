"""agent-bom: AI Bill of Materials generator for AI agents and MCP servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agent-bom")
except PackageNotFoundError:
    __version__ = "0.31.2"
