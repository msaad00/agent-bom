"""AI component source scanning — detect SDK imports, model refs, API keys, shadow AI.

Public API::

    from agent_bom.ai_components import scan_source, AIComponent, AIComponentReport

    report = scan_source("/path/to/project")
"""

from agent_bom.ai_components.models import (
    AIComponent,
    AIComponentReport,
    AIComponentSeverity,
    AIComponentType,
)
from agent_bom.ai_components.scanner import scan_source

__all__ = [
    "AIComponent",
    "AIComponentReport",
    "AIComponentSeverity",
    "AIComponentType",
    "scan_source",
]
