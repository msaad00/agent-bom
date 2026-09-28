"""Tenant policy lookups and control-plane policy evaluation for gateway adapters."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent_bom.agent_identity import ANONYMOUS
from agent_bom.api.gateway_request import _sanitize_for_log
from agent_bom.runtime.gateway_settings import GatewaySettings
from agent_bom.security import sanitize_text

# Preserve the gateway's existing log channel across this adapter extraction.
logger = logging.getLogger("agent_bom.gateway_server")
_DRIFT_INCIDENT_LOOKUP_CAP = 200
_CONDITIONAL_ACCESS_EVAL_FAILED = "conditional access evaluation failed"


def _agent_cost_anomaly(tenant_id: str, source_agent: str) -> tuple[bool, str]:
    """Return (anomalous, reason) if ``source_agent`` currently has a cost-spike
    anomaly vs the tenant fleet. Cached upstream; fail-open on any store error."""
    if not source_agent:
        return False, ""
    try:
        from agent_bom.api.anomaly import cost_anomalous_agents

        flagged = cost_anomalous_agents(tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway anomaly check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False, ""
    info = flagged.get(source_agent)
    if info:
        return True, (f"agent '{source_agent}' has anomalous spend (z={info.get('z_score')}) vs the tenant fleet baseline")
    return False, ""


def _fleet_containment_reason(tenant_id: str, source_agent: str) -> str | None:
    """Return a containment reason for an exact fleet ID or failed lookup.

    Resolves one agent through an indexed lookup rather than paging the roster:
    this runs on every relay call, so its cost must not scale with fleet size.
    Lookup failures block in enforce mode and remain visible in warn mode.

    Blocking I/O — call it off the event loop.
    """
    if not source_agent:
        return None
    try:
        from agent_bom.api.fleet_store import FleetLifecycleState, find_fleet_agent
        from agent_bom.api.stores import _get_fleet_store

        agent = find_fleet_agent(_get_fleet_store(), tenant_id, source_agent)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway fleet check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return "fleet_lookup_unavailable"
    if agent is None:
        return None
    return "fleet_quarantine" if getattr(agent, "lifecycle_state", None) == FleetLifecycleState.QUARANTINED else None


def _agent_identity_revoked(tenant_id: str, source_agent: str) -> tuple[bool, bool, bool]:
    """Return ``(revoked, lookup_incomplete, lookup_failed)`` for a caller with
    no managed token.

    ``identity_for_token`` only matches an agent-bom-issued ``abi_`` token, so a
    JWKS/OIDC JWT or an opaque ``policy.agent_tokens`` caller previously bypassed
    identity revocation entirely.

    The two failure signals are deliberately distinct because they warrant
    different verdicts:

    * ``lookup_incomplete`` — the store answered, but with a result it knows is
      partial. A revoked row may be sitting in the untraversed tail, so the
      answer is unusable and the relay denies unconditionally.
    * ``lookup_failed`` — the store did not answer at all. Fail-open, gated on
      posture, so an identity-store outage never becomes a fleet-wide outage.

    Blocking I/O — call it off the event loop.
    """
    if not source_agent or source_agent == ANONYMOUS:
        return False, False, False
    try:
        from agent_bom.api.agent_identity_store import agent_identity_revoked, get_agent_identity_store

        revoked, lookup_incomplete = agent_identity_revoked(get_agent_identity_store(), tenant_id, source_agent)
        return revoked, lookup_incomplete, False
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway agent identity revocation check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False, False, True


@dataclass(frozen=True)
class _DriftLookup:
    violates: bool = False
    unavailable: bool = False
    reason: str = ""


def _open_drift_violates_tool(tenant_id: str, blueprint_id: str, tool_name: str) -> _DriftLookup:
    """Look up a tool violation for a caller's resolved role blueprint.

    Drift incidents are keyed by ``blueprint_id``.  They are never keyed by an
    agent id, so callers must resolve the managed identity -> blueprint binding
    before invoking this function.  Store unavailability is returned explicitly
    so secured enforce-mode callers can fail closed while development/audit
    modes can remain observable without silently inventing a match.
    """
    if not blueprint_id or not tool_name:
        return _DriftLookup()
    try:
        from agent_bom.api.drift_incident_store import get_drift_incident_store

        incidents = get_drift_incident_store().list(tenant_id, include_resolved=False, limit=_DRIFT_INCIDENT_LOOKUP_CAP)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway drift check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return _DriftLookup(unavailable=True, reason="drift incident store unavailable")
    blueprint_key = blueprint_id.strip().lower().replace("-", "_")
    for incident in incidents:
        incident_blueprint = (getattr(incident, "blueprint_id", "") or "").strip().lower().replace("-", "_")
        if incident_blueprint != blueprint_key:
            continue
        drifted_tools = {
            str(v.get("tool_name", "")).strip() for v in (getattr(incident, "top_violations", None) or []) if isinstance(v, dict)
        }
        if tool_name in drifted_tools:
            return _DriftLookup(
                violates=True,
                reason=f"tool '{tool_name}' is outside role blueprint '{blueprint_id}'",
            )
    if len(incidents) >= _DRIFT_INCIDENT_LOOKUP_CAP:
        # The open-incident set was capped, so a violation may exist in the tail
        # we never inspected. Surface this as unavailable (partial) instead of a
        # clean pass, so enforce-mode callers fail closed rather than silently
        # under-enforce for the tenant's tail incidents.
        logger.warning(
            "gateway drift check truncated at %d open incidents for tenant; enforcement coverage is partial",
            _DRIFT_INCIDENT_LOOKUP_CAP,
        )
        return _DriftLookup(
            unavailable=True,
            reason=f"open drift incidents exceed lookup cap ({_DRIFT_INCIDENT_LOOKUP_CAP}); enforcement coverage partial",
        )
    return _DriftLookup()


def _validate_gateway_rule_patterns(policies: list[Any]) -> tuple[bool, str]:
    """Fail closed when a control-plane rule carries an invalid regex pattern."""
    import re

    for policy in policies:
        for rule in policy.rules:
            if rule.tool_name_pattern:
                try:
                    re.compile(rule.tool_name_pattern)
                except re.error:
                    logger.error(
                        "gateway control-plane bundle: invalid tool_name_pattern in rule %s (policy %s); failing closed",
                        rule.id,
                        policy.policy_id,
                    )
                    return False, "control-plane policy malformed"
            for arg_name, arg_regex in (rule.arg_pattern or {}).items():
                try:
                    re.compile(arg_regex)
                except re.error:
                    logger.error(
                        "gateway control-plane bundle: invalid arg_pattern for %s in rule %s (policy %s); failing closed",
                        arg_name,
                        rule.id,
                        policy.policy_id,
                    )
                    return False, "control-plane policy malformed"
    return True, ""


def _evaluate_control_plane_bundle(
    policy_dicts: list[dict[str, Any]], source_agent: str, tool_name: str, arguments: dict
) -> tuple[bool, str]:
    """Enforce control-plane GatewayPolicy binding for one relayed call.

    Mirrors the per-MCP proxy: policies are scoped to the resolved source_agent
    via bound_agents before evaluation, so a policy bound to other agents never
    applies here. Returns ``(allowed, reason)``; an empty bundle allows.
    """
    if not policy_dicts:
        return True, ""
    try:
        from agent_bom.api.policy_store import GatewayPolicy
        from agent_bom.gateway import evaluate_gateway_policy_bundle

        policies = []
        parse_errors = 0
        for item in policy_dicts:
            try:
                policies.append(GatewayPolicy(**item))
            except (TypeError, ValueError):
                parse_errors += 1
                continue
        if not policies:
            # The bundle was configured but nothing parsed — an operator typo must
            # not silently disable all control-plane enforcement. Fail closed.
            if parse_errors:
                logger.error(
                    "gateway control-plane bundle: all %d policy/policies failed to parse; failing closed",
                    parse_errors,
                )
                return False, "control-plane policy malformed"
            return True, ""
        if parse_errors:
            logger.error(
                "gateway control-plane bundle: %d policy/policies failed to parse; failing closed",
                parse_errors,
            )
            return False, "control-plane policy malformed"
        patterns_ok, pattern_reason = _validate_gateway_rule_patterns(policies)
        if not patterns_ok:
            return False, pattern_reason
        return evaluate_gateway_policy_bundle(policies, source_agent, tool_name, arguments)
    except Exception as exc:  # noqa: BLE001
        # Fail closed: a bundle that cannot be evaluated must not silently pass.
        logger.warning("gateway control-plane bundle evaluation failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False, "control-plane policy evaluation error"


def _conditional_access_fail_closed(tenant_id: str) -> tuple[bool, str, str]:
    """Decide the conditional-access outcome after an evaluation error, fail-closed.

    The primary evaluation (``evaluate_conditional_access_for_request``) raised, so
    we cannot trust its verdict. A conditional-access ``deny``/``require`` policy
    that would otherwise block the call MUST NOT be silently bypassed (§7 fail
    closed). But we also must not turn a flaky store into a blanket outage for
    tenants that never configured the feature.

    Resolution:
    - Re-read the tenant's active conditional-access policies with a cheap,
      independent lookup. If that read succeeds and finds **no** policies, there
      is no gate to bypass → allow.
    - If the tenant HAS one or more active conditional-access policies → deny.
    - If we cannot even determine whether policies exist (the lookup also
      raised — e.g. the store is unavailable), we cannot prove the gate is empty,
      so deny. Only a positively-confirmed empty policy set opens the gate.

    Returns ``(allowed, reason, policy_id)`` matching the primary evaluator.
    """
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        policies = get_agent_identity_store().list_conditional_policies(tenant_id, include_disabled=False, limit=1)
    except Exception:  # noqa: BLE001 — cannot confirm an empty gate → fail closed
        return False, _CONDITIONAL_ACCESS_EVAL_FAILED, ""
    if not policies:
        return True, "", ""
    return False, _CONDITIONAL_ACCESS_EVAL_FAILED, ""


def _warn_on_quarantined_agents(settings: GatewaySettings) -> None:
    """Name the agents that fleet enforcement will block, once, at boot.

    ``fleet_enforcement_mode`` now defaults to ``enforce``. An operator upgrading
    with a stale QUARANTINED row would otherwise discover the new behaviour as
    unexplained traffic loss — especially likely because releasing an agent did
    not disable its deny policy until this release. Best-effort and silent on
    error: this is an advisory log, never a boot gate.
    """
    if settings.fleet_enforcement_mode != "enforce":
        return
    try:
        from agent_bom.api.fleet_store import FleetLifecycleState
        from agent_bom.api.stores import _get_fleet_store

        # The relay resolves a tenant per request; at boot only the default
        # tenant is knowable, which is the single-tenant self-host shape this
        # warning exists for.
        quarantined = [
            (getattr(a, "name", "") or getattr(a, "agent_id", ""))
            for a in _get_fleet_store().list_by_tenant("default")
            if getattr(a, "lifecycle_state", None) == FleetLifecycleState.QUARANTINED
        ]
    except Exception:  # noqa: BLE001
        return
    if quarantined:
        logger.warning(
            "fleet enforcement is active: %d quarantined agent(s) will be blocked at this gateway: %s "
            "(opt out with --fleet-enforcement off)",
            len(quarantined),
            ", ".join(sorted(_sanitize_for_log(name) for name in quarantined)[:20]),
        )
