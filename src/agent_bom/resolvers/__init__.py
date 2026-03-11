"""Version resolvers for installed and running package versions.

Complements static lockfile parsing with runtime introspection to close
the declared → installed → running version gap (P0 #562).
"""

from agent_bom.resolvers.runtime_resolver import (  # noqa: F401
    resolve_go_versions,
    resolve_npm_versions,
    resolve_pip_versions,
)
