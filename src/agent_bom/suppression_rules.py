"""Tenant-scoped finding suppression rules.

Suppression is modeled as an evidence overlay, not deletion. A matching rule
sets the blast-radius item to non-actionable and preserves the original risk
score for audit/export consumers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.api.exception_store import ExceptionStore, VulnException

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

_SUPPRESSING_FEEDBACK_STATES = {
    "false_positive",
    "accepted_risk",
    "not_applicable",
    "fixed_verified",
}


def feedback_state_from_reason(reason: str) -> tuple[str | None, str]:
    """Parse ``[finding_feedback:state] reason`` values from the exception store."""
    marker = "[finding_feedback:"
    if not reason.startswith(marker):
        return None, reason
    closing = reason.find("]")
    if closing <= len(marker):
        return None, reason
    state = reason[len(marker) : closing].strip()
    clean_reason = reason[closing + 1 :].strip()
    return state or None, clean_reason


def is_suppressing_exception(exc: VulnException) -> bool:
    """Return whether an exception/feedback row suppresses scanner actionability."""
    state, _reason = feedback_state_from_reason(exc.reason)
    return state in _SUPPRESSING_FEEDBACK_STATES or state is None


def apply_tenant_suppression_rules(
    blast_radii: list["BlastRadius"],
    store: ExceptionStore,
    *,
    tenant_id: str = "default",
) -> dict[str, int]:
    """Apply tenant-scoped exception/feedback rules to blast-radius findings.

    Findings remain in the list with suppression metadata. This preserves
    original evidence while preventing suppressed findings from counting as
    actionable in downstream output.
    """
    summary = {"evaluated": len(blast_radii), "suppressed": 0}
    for br in blast_radii:
        server_names = [server.name for server in br.affected_servers] or [""]
        match = _find_matching_exception(store, br.vulnerability.id, br.package.name, server_names, tenant_id)
        if match is None or not is_suppressing_exception(match):
            continue
        state, reason = feedback_state_from_reason(match.reason)
        br.suppressed = True
        br.suppression_id = match.exception_id
        br.suppression_state = state or "exception"
        br.suppression_reason = reason or match.reason
        br.unsuppressed_risk_score = br.risk_score
        br.risk_score = 0.0
        br.transitive_risk_score = 0.0
        summary["suppressed"] += 1
    return summary


def _find_matching_exception(
    store: ExceptionStore,
    vuln_id: str,
    package_name: str,
    server_names: list[str],
    tenant_id: str,
) -> VulnException | None:
    for server_name in server_names:
        match = store.find_matching(vuln_id, package_name, server_name=server_name, tenant_id=tenant_id)
        if match is not None:
            return match
    return None
