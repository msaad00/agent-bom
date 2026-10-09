"""Relay tool-policy layer: graph reachability enforcement (consume direction).

Prefers the current signed correlation bundle, then falls back to the legacy
static report. Bundle verification failures expose only stable reason codes.
Missing evidence keeps the legacy allow posture unless the operator selected
``failure_mode=deny``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent_bom.api.gateway_relay_context import RelayContext, RelayRuntime, ToolDecision, _emit_gateway_governance_event
from agent_bom.api.gateway_request import _sanitize_for_log
from agent_bom.runtime.correlation_facts import VerifiedRuntimeFacts
from agent_bom.runtime.graph_reachability import ReachabilityMap
from agent_bom.security import sanitize_text

logger = logging.getLogger("agent_bom.gateway_server")


@dataclass(frozen=True)
class _ReachabilityEvidence:
    verified: VerifiedRuntimeFacts | None
    effective: ReachabilityMap
    request_tenant_mismatch: bool
    analysis_incomplete: bool
    bundle_unavailable: bool
    strict_evidence_missing: bool

    def provenance(self) -> dict[str, Any]:
        facts = self.verified
        return {
            "evidence_source": "correlation_bundle" if facts is not None else "scan_report",
            "correlation_id": facts.correlation_id if facts is not None else "",
            "manifest_sha256": facts.manifest_sha256 if facts is not None else "",
            "evidence_freshness": facts.evidence_freshness if facts is not None else "unknown",
        }


def _resolve_evidence(runtime: RelayRuntime, ctx: RelayContext) -> _ReachabilityEvidence:
    poller = runtime.runtime_facts_poller
    fetched = poller.current() if poller is not None else None
    tenant_mismatch = bool(fetched is not None and fetched.tenant_id != ctx.tenant_id)
    verified = None if tenant_mismatch else fetched
    analysis_incomplete = bool(verified is not None and not verified.analysis_complete)
    configured = runtime.runtime_facts_configured
    return _ReachabilityEvidence(
        verified=verified,
        effective=verified.reachability if verified is not None else runtime.reachability_map,
        request_tenant_mismatch=tenant_mismatch,
        analysis_incomplete=analysis_incomplete,
        bundle_unavailable=configured and (verified is None or analysis_incomplete),
        strict_evidence_missing=runtime.settings.graph_reachability_failure_mode == "deny"
        and (analysis_incomplete or (verified is None and (configured or not runtime.reachability_map))),
    )


def _unavailable_reason_code(runtime: RelayRuntime, evidence: _ReachabilityEvidence) -> str:
    poller = runtime.runtime_facts_poller
    if evidence.request_tenant_mismatch:
        return "request_tenant_mismatch"
    if evidence.analysis_incomplete:
        return "analysis_incomplete"
    if runtime.runtime_facts_config_error:
        return runtime.runtime_facts_config_error
    if poller is not None and poller.last_error:
        return str(poller.last_error)
    if runtime.settings.graph_reachability_path is not None:
        return "static_evidence_unavailable"
    return "evidence_not_configured"


async def _record_missing_evidence(
    runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision, evidence: _ReachabilityEvidence
) -> None:
    reason_code = _unavailable_reason_code(runtime, evidence) or "bundle_unavailable"
    await runtime.audit(
        {
            "action": "gateway.graph_reachability_evidence_unavailable",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "tool": decision.tool_name,
            "failure_mode": runtime.settings.graph_reachability_failure_mode,
            "reason_code": reason_code,
        }
    )
    if not evidence.strict_evidence_missing:
        return
    decision.deny("signed graph reachability evidence unavailable", "graph_reachability_evidence")
    _emit_gateway_governance_event(
        "graph_reachability.evidence_unavailable",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={"source_agent": ctx.source_agent, "tool": decision.tool_name, "failure_mode": "deny", "reason_code": reason_code},
    )


def _find_reach_hit(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision, evidence: _ReachabilityEvidence) -> Any:
    try:
        if decision.allowed and evidence.effective:
            return evidence.effective.reaches_privileged(ctx.source_agent, decision.tool_name)
    except Exception as exc:  # noqa: BLE001 — fail-open, never break the relay
        logger.warning("gateway graph-reachability check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        if runtime.settings.graph_reachability_failure_mode == "deny":
            decision.deny("graph reachability evaluation unavailable", "graph_reachability_evidence")
    return None


async def _act_on_reach_hit(
    runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision, evidence: _ReachabilityEvidence, reach_hit: Any
) -> None:
    reach_reason = (
        f"agent '{ctx.source_agent}' statically reaches privileged/credential node "
        f"'{decision.tool_name}' ({reach_hit.rule_id}); blocking pre-emptively"
    )
    details = {
        "source_agent": ctx.source_agent,
        "tool": decision.tool_name,
        "rule_id": reach_hit.rule_id,
        "severity": reach_hit.severity,
        "reason": reach_reason,
        **evidence.provenance(),
    }
    base = {"upstream": ctx.upstream.name, "tenant_id": ctx.tenant_id}
    if runtime.settings.graph_reachability_enforcement_mode != "enforce":
        await runtime.audit({"action": "gateway.graph_reachability_warned", **base, **details})
        return
    decision.deny(reach_reason, "graph_reachability")
    await runtime.audit({"action": "gateway.graph_reachability_blocked", **base, **details})
    _emit_gateway_governance_event("graph_reachability.blocked", tenant_id=ctx.tenant_id, subject_id=ctx.source_agent, payload=details)


async def apply_graph_reachability(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Block or flag an agent that statically reaches a privileged node via this tool."""
    if not decision.allowed or runtime.settings.graph_reachability_enforcement_mode not in ("warn", "enforce"):
        return
    evidence = _resolve_evidence(runtime, ctx)
    if evidence.bundle_unavailable or evidence.strict_evidence_missing:
        await _record_missing_evidence(runtime, ctx, decision, evidence)
    reach_hit = _find_reach_hit(runtime, ctx, decision, evidence)
    if reach_hit is not None:
        await _act_on_reach_hit(runtime, ctx, decision, evidence, reach_hit)
