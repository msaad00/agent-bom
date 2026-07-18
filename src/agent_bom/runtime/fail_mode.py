"""Fail-open / fail-closed posture matrix for the runtime gateway.

Every enforcement subsystem in ``agent_bom.gateway_server`` makes a decision
about what happens when its *own* machinery fails (a policy file that will not
load, a store that errors, an evaluator that raises). Those decisions were
previously scattered across inline comments; this module is the single
publishable inventory so operators can audit the posture without reading the
relay source.

Two invariants keep the matrix honest:

- Advisory/enrichment lanes (spend telemetry, drift, fleet state, reachability,
  audit export) fail OPEN by design: their store errors must never take the
  data plane down.
- Security decision lanes (identity, conditional access, control-plane
  bundles, device-posture-gated policies) fail CLOSED and are NOT softened by
  ``AGENT_BOM_GATEWAY_FAIL_MODE`` — only the policy engine, firewall policy
  load, and policy plugins honour that knob (default ``closed``).

The matrix is exposed read-only on the gateway ``/healthz`` endpoint under
``fail_mode_runtime`` and documented in ``docs/RUNTIME_FAIL_MODES.md``. Tests
in ``tests/test_runtime_fail_mode.py`` pin each entry to the implemented
behavior; changing a posture in ``gateway_server.py`` requires updating both.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "FailPosture",
    "SubsystemFailMode",
    "GATEWAY_FAIL_MODE_MATRIX",
    "gateway_fail_mode_matrix",
]


class FailPosture(str, Enum):
    """What a subsystem does when its own machinery fails."""

    OPEN = "fail_open"  # failure never blocks the relay
    CLOSED = "fail_closed"  # failure denies the request (or refuses startup)


@dataclass(frozen=True)
class SubsystemFailMode:
    """Documented failure posture for one gateway enforcement subsystem."""

    subsystem: str
    # Posture under the default gateway fail mode ("closed").
    default_posture: FailPosture
    # True only for subsystems whose posture flips with AGENT_BOM_GATEWAY_FAIL_MODE.
    follows_gateway_fail_mode: bool
    # The operator control governing this posture, or "none (fixed)".
    control: str
    # What actually happens when this subsystem's machinery fails.
    on_failure: str


GATEWAY_FAIL_MODE_MATRIX: tuple[SubsystemFailMode, ...] = (
    SubsystemFailMode(
        subsystem="policy_engine",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=True,
        control="AGENT_BOM_GATEWAY_FAIL_MODE (default: closed)",
        on_failure=(
            "A configured policy file that never loaded denies every relay "
            "request in fail-closed mode; fail-open forwards against the "
            "empty default-allow policy."
        ),
    ),
    SubsystemFailMode(
        subsystem="firewall_policy",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=True,
        control="AGENT_BOM_GATEWAY_FAIL_MODE (default: closed)",
        on_failure=(
            "A configured inter-agent firewall policy file that never loaded "
            "denies requests in fail-closed mode instead of falling back to "
            "default-allow."
        ),
    ),
    SubsystemFailMode(
        subsystem="control_plane_policy_bundle",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=False,
        control="none (fixed)",
        on_failure=(
            "A control-plane bundle whose policies all fail to parse, carry "
            "an invalid regex, or raise during evaluation denies the request; "
            "an operator typo never silently disables enforcement."
        ),
    ),
    SubsystemFailMode(
        subsystem="policy_plugins",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=True,
        control="AGENT_BOM_GATEWAY_FAIL_MODE (default: closed)",
        on_failure=("A policy-plugin evaluation error denies the request in fail-closed mode and allows it in fail-open mode."),
    ),
    SubsystemFailMode(
        subsystem="conditional_access",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=False,
        control="none (fixed)",
        on_failure=(
            "A conditional-access evaluation error denies the request "
            "whenever any conditional-access policy exists for the tenant, "
            "or when the policy store cannot be read to prove none exist."
        ),
    ),
    SubsystemFailMode(
        subsystem="caller_identity",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=False,
        control="AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS (missing identity only)",
        on_failure=(
            "An invalid or revoked agent-identity token always denies. A "
            "fully-missing identity denies on non-loopback listeners unless "
            "the explicit anonymous-agents opt-out is set."
        ),
    ),
    SubsystemFailMode(
        subsystem="runtime_rate_limit",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=False,
        control="AGENT_BOM_POSTGRES_URL / AGENT_BOM_GATEWAY_REPLICAS",
        on_failure=(
            "A configured Postgres limiter that cannot initialize, or a "
            "multi-replica deployment without a shared store, refuses to "
            "start the gateway rather than degrading to process-local state."
        ),
    ),
    SubsystemFailMode(
        subsystem="spend_budgets",
        default_posture=FailPosture.OPEN,
        follows_gateway_fail_mode=False,
        control="none (fixed)",
        on_failure=(
            "Cost-store errors during agent/tenant, cost-center, and owner "
            "budget checks are logged and never block the relay; only a "
            "successfully evaluated enforce-mode budget can deny."
        ),
    ),
    SubsystemFailMode(
        subsystem="cost_anomaly_enforcement",
        default_posture=FailPosture.OPEN,
        follows_gateway_fail_mode=False,
        control="anomaly_enforcement_mode (default: off)",
        on_failure="Cost-store errors during the spend-anomaly check never block the relay.",
    ),
    SubsystemFailMode(
        subsystem="fleet_quarantine_enforcement",
        default_posture=FailPosture.OPEN,
        follows_gateway_fail_mode=False,
        control="fleet_enforcement_mode (default: off)",
        on_failure="Fleet-store errors during the quarantine lookup are logged and never block the relay.",
    ),
    SubsystemFailMode(
        subsystem="drift_enforcement",
        default_posture=FailPosture.OPEN,
        follows_gateway_fail_mode=False,
        control="drift_enforcement_mode (default: off)",
        on_failure="Drift-store errors during the behavioral-drift lookup never block the relay.",
    ),
    SubsystemFailMode(
        subsystem="graph_reachability_enforcement",
        default_posture=FailPosture.OPEN,
        follows_gateway_fail_mode=False,
        control="graph_reachability_enforcement_mode (default: off)",
        on_failure="A reachability-map evaluation error is logged and never blocks the relay.",
    ),
    SubsystemFailMode(
        subsystem="device_posture_enrichment",
        default_posture=FailPosture.CLOSED,
        follows_gateway_fail_mode=False,
        control="none (fixed)",
        on_failure=(
            "A device-posture enrichment error leaves the device state "
            "unknown, so any conditional policy that requires a managed, "
            "compliant, or disk-encrypted device denies the request."
        ),
    ),
    SubsystemFailMode(
        subsystem="audit_export",
        default_posture=FailPosture.OPEN,
        follows_gateway_fail_mode=False,
        control="none (fixed)",
        on_failure=(
            "Audit-sink, SIEM webhook, and OCSF interop delivery failures never block the relay; decisions are made before export."
        ),
    ),
)


def gateway_fail_mode_matrix(fail_mode: str) -> list[dict[str, object]]:
    """Return the effective per-subsystem posture for a resolved gateway fail mode.

    ``fail_mode`` must already be resolved to ``"open"`` or ``"closed"``
    (see ``agent_bom.proxy_policy.resolve_fail_mode``). Entries with
    ``follows_gateway_fail_mode`` report the flipped posture in open mode;
    fixed entries always report their default.
    """
    if fail_mode not in ("open", "closed"):
        raise ValueError(f"fail_mode must be 'open' or 'closed', got {fail_mode!r}")
    rows: list[dict[str, object]] = []
    for entry in GATEWAY_FAIL_MODE_MATRIX:
        if entry.follows_gateway_fail_mode:
            posture = FailPosture.CLOSED if fail_mode == "closed" else FailPosture.OPEN
        else:
            posture = entry.default_posture
        rows.append(
            {
                "subsystem": entry.subsystem,
                "posture": posture.value,
                "follows_gateway_fail_mode": entry.follows_gateway_fail_mode,
                "control": entry.control,
                "on_failure": entry.on_failure,
            }
        )
    return rows
