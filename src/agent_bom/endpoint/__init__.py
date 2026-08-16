"""Endpoint and workstation evidence contracts."""

from agent_bom.endpoint.inventory import collect_endpoint_inventory
from agent_bom.endpoint.scope import workstation_scan_scopes

__all__ = ["collect_endpoint_inventory", "workstation_scan_scopes"]
