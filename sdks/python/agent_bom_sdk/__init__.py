"""Thin Python SDK alias for the packaged agent-bom control-plane client.

The control-plane client ships in the ``agent-bom`` wheel as
``agent_bom.client.AgentBomClient``. This package re-exports it under the
``agent_bom_sdk`` name so language-agnostic SDK tooling can depend on a stable
import path that mirrors the Go (``sdks/go``) and TypeScript
(``@agent-bom/client``) packages. It adds no behaviour of its own.
"""

from __future__ import annotations

from agent_bom.client import AgentBomApiError, AgentBomClient

__all__ = ["AgentBomApiError", "AgentBomClient"]
