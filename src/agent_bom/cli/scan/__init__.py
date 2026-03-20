"""Backward-compat shim — makes agent_bom.cli.scan an alias for agent_bom.cli.agents.

Patches like ``patch("agent_bom.cli.scan.discover_all")`` work because
this module IS the agents module (via sys.modules aliasing).
"""

import sys

import agent_bom.cli.agents as _agents_module

# Make this package share the same module object as agents/
# so patch("agent_bom.cli.scan.X") patches the SAME namespace.
sys.modules[__name__] = _agents_module
