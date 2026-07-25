"""Guards for evaluating with the control plane's *own* cloud identity.

Most cloud work runs against a tenant's stored, scoped connection. A few
surfaces instead evaluate with whatever ambient credentials the process itself
holds — an instance role, an assumed role, a mounted profile. That is a
different trust level, so it is off unless an operator turns it on, and the
caller never chooses which credential gets spent.

The guard lives here rather than in a route because REST and the MCP tool call
the same benchmark. Gating only one of them would leave the other as an open
path to the same credentials.
"""

from __future__ import annotations

import os

AMBIENT_CIS_ENV = "AGENT_BOM_CLOUD_CIS_BENCHMARK"
AWS_PROFILE_ENV = "AGENT_BOM_AWS_PROFILE"

_TRUTHY = frozenset({"1", "true", "yes", "on"})

DISABLED_NOTE = (
    "Ambient-credential CIS benchmark is opt-in. Set AGENT_BOM_CLOUD_CIS_BENCHMARK=1 to allow this control "
    "plane to evaluate its own cloud identity. Prefer scanning through a tenant cloud connection instead."
)

PROFILE_REJECTED_NOTE = (
    "The profile parameter is not accepted. The control plane evaluates its configured credentials; "
    "set AGENT_BOM_AWS_PROFILE on the server to choose a different one."
)


def ambient_cis_enabled() -> bool:
    """Whether an operator allows ambient-credential CIS evaluation.

    Read live so the flag can be flipped without a redeploy, matching how the
    cloud inventory surface resolves its own per-provider opt-ins.
    """
    return (os.environ.get(AMBIENT_CIS_ENV) or "").strip().lower() in _TRUTHY


def configured_aws_profile() -> str | None:
    """Operator-selected AWS profile, if any. Never caller-supplied."""
    return (os.environ.get(AWS_PROFILE_ENV) or "").strip() or None


def disabled_payload(provider: str) -> dict[str, str]:
    """Envelope returned when ambient evaluation is not enabled.

    Carries ``error`` so headless callers that branch on it degrade the same way
    they do for a missing SDK, and ``status`` so operators can tell a disabled
    surface from a failed one.
    """
    return {
        "provider": provider,
        "status": "disabled",
        "error": DISABLED_NOTE,
    }
