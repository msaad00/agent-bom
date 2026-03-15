"""agent-bom: Security scanner for AI infrastructure — from agent to runtime."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agent-bom")
except PackageNotFoundError:
    __version__ = "0.70.11"
