"""Shared scan option contract for CLI, SDK, and API surfaces.

The full ``agents`` command still owns the broad scanner option surface. This
module captures the stable simple-scan subset that already exists across the
public Python API, remediation flow, and REST scan request model so those
surfaces do not keep growing separate option names and defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ScanConfig:
    """Inputs for a default local scan invocation."""

    project: str | None = None
    demo: bool = False
    offline: bool = False
    enrich: bool = False
    compliance: bool = False
    resolve_transitive: bool = False
    max_depth: int = 3
    blast_radius_depth: int = 2
    quiet: bool = False

    def to_api_payload(self) -> dict[str, Any]:
        """Return the overlapping POST /v1/scan payload fields.

        The API does not currently accept demo/compliance/quiet flags. The
        payload deliberately includes only fields the API contract can consume
        today, so this helper is safe for future CLI-as-control-plane routing.
        """
        payload: dict[str, Any] = {
            "offline": self.offline,
            "enrich": self.enrich,
        }
        if self.project:
            payload["agent_projects"] = [self.project]
        return payload


def scan_config_from_api_request(request: object, *, project: str | None = None, quiet: bool = False) -> ScanConfig:
    """Map the overlapping POST /v1/scan request fields to ``ScanConfig``.

    ``ScanRequest`` lives under ``agent_bom.api`` and should not be imported by
    CLI-only code. Accepting an object with matching attributes keeps this
    contract independent and easy to test from both sides.
    """
    request_project = project
    if request_project is None:
        agent_projects = getattr(request, "agent_projects", None)
        if isinstance(agent_projects, list) and agent_projects:
            request_project = str(agent_projects[0])
    return ScanConfig(
        project=request_project,
        offline=bool(getattr(request, "offline", False)),
        enrich=bool(getattr(request, "enrich", False)),
        quiet=quiet,
    )
