"""Observe->enforce bridge — confirmed-vulnerable + actively-called tools -> block-rule proposals.

Consumes :class:`~agent_bom.runtime_correlation.CorrelationReport` output (tools
that are BOTH confirmed-vulnerable in a scan AND actually invoked in proxy audit
traces) and emits gateway block-rule *proposals*, reusing the existing
:class:`~agent_bom.api.policy_store.GatewayRule` / ``GatewayPolicy`` model.

Security model (default = propose, never silently enforce):

* Proposals are wrapped in an **audit-mode** ``GatewayPolicy`` by default. The
  gateway downgrades audit-mode block rules to advisory ``warn`` (see
  ``gateway.gateway_policies_to_proxy_bundle``), so a proposal never blocks live
  traffic on its own.
* An **enforce-mode** policy is produced only under the explicit ``enforce``
  opt-in. Even then the operator must import/enable the policy through the
  existing gateway policy layer for it to take effect — there is no path that
  auto-blocks production traffic without operator intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.policy_store import GatewayPolicy, GatewayRule, PolicyMode
from agent_bom.runtime_correlation import CorrelationReport

SCHEMA_VERSION = "gateway.observe_enforce.v1"
PROPOSAL_POLICY_ID = "agent-bom-observe-enforce"
PROPOSAL_POLICY_NAME = "agent-bom observe-to-enforce (auto-proposed)"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(tool_name: str) -> str:
    slug = _SLUG_RE.sub("-", tool_name.strip().lower()).strip("-")
    return slug or "tool"


@dataclass
class BlockRuleProposal:
    """One proposed gateway block rule for a confirmed-vulnerable, called tool."""

    tool_name: str
    rule: GatewayRule
    vulnerability_ids: list[str]
    top_severity: str
    call_count: int
    correlated_risk_score: float
    was_blocked: bool
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "rule": self.rule.model_dump(mode="json"),
            "vulnerability_ids": list(self.vulnerability_ids),
            "top_severity": self.top_severity,
            "call_count": self.call_count,
            "correlated_risk_score": round(self.correlated_risk_score, 2),
            "was_blocked": self.was_blocked,
            "rationale": self.rationale,
        }


@dataclass
class ObserveEnforceResult:
    """Outcome of the observe->enforce bridge."""

    proposals: list[BlockRuleProposal]
    policy: GatewayPolicy
    enforced: bool
    mode: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": self.mode,
            "enforced": self.enforced,
            "generated_at": self.generated_at,
            "proposal_count": len(self.proposals),
            "proposals": [p.to_dict() for p in self.proposals],
            "policy": self.policy.model_dump(mode="json"),
        }


def propose_block_rules(
    correlation: CorrelationReport,
    *,
    enforce: bool = False,
    tenant_id: str = "default",
) -> ObserveEnforceResult:
    """Turn runtime correlation into gateway block-rule proposals.

    A tool earns a block-rule proposal only when it is BOTH confirmed-vulnerable
    (present in a correlated scan finding) AND actively-called (``call_count >=
    1``) in the audit traces. Multiple CVEs on the same tool collapse into one
    rule; the tool's highest-risk finding drives ordering (the correlation
    report is already sorted by correlated risk, highest first).

    Args:
        correlation: The runtime<->scan correlation report.
        enforce: Explicit opt-in. When ``False`` (default) the returned policy is
            audit-mode (advisory / warn only). When ``True`` it is enforce-mode.
        tenant_id: Tenant that owns the generated policy.

    Returns:
        An :class:`ObserveEnforceResult` carrying the per-tool proposals and a
        single ``GatewayPolicy`` bundling their rules.
    """
    # Group correlated findings by called tool, preserving highest-risk-first order.
    grouped: dict[str, list] = {}
    for finding in correlation.correlated_findings:
        if finding.call_count < 1:
            continue  # theoretical only — never called
        grouped.setdefault(finding.tool_name, []).append(finding)

    proposals: list[BlockRuleProposal] = []
    for tool_name, findings in grouped.items():
        vuln_ids: list[str] = []
        for f in findings:
            if f.vulnerability_id and f.vulnerability_id not in vuln_ids:
                vuln_ids.append(f.vulnerability_id)
        top = findings[0]
        was_blocked = any(f.was_blocked for f in findings)
        rationale = (
            f"Tool '{tool_name}' is confirmed-vulnerable ({', '.join(vuln_ids)}) and was "
            f"actively invoked {top.call_count} time(s) in runtime traces "
            f"(correlated risk {top.correlated_risk_score:.1f})."
        )
        rule = GatewayRule(
            id=f"observe-enforce-{_slug(tool_name)}",
            description=rationale,
            action="block",
            block_tools=[tool_name],
        )
        proposals.append(
            BlockRuleProposal(
                tool_name=tool_name,
                rule=rule,
                vulnerability_ids=vuln_ids,
                top_severity=top.severity,
                call_count=top.call_count,
                correlated_risk_score=top.correlated_risk_score,
                was_blocked=was_blocked,
                rationale=rationale,
            )
        )

    mode = PolicyMode.ENFORCE if enforce else PolicyMode.AUDIT
    now = datetime.now(timezone.utc).isoformat()
    policy = GatewayPolicy(
        policy_id=PROPOSAL_POLICY_ID,
        name=PROPOSAL_POLICY_NAME,
        description=(
            "Auto-proposed block rules for tools that are both confirmed-vulnerable and "
            "actively invoked in runtime traces. Audit mode proposes (advisory warn only); "
            "enforce mode blocks and is produced only under an explicit operator opt-in."
        ),
        mode=mode,
        rules=[p.rule for p in proposals],
        created_at=now,
        updated_at=now,
        enabled=True,
        tenant_id=tenant_id,
    )

    return ObserveEnforceResult(
        proposals=proposals,
        policy=policy,
        enforced=enforce,
        mode=mode.value,
    )


__all__ = [
    "SCHEMA_VERSION",
    "PROPOSAL_POLICY_ID",
    "PROPOSAL_POLICY_NAME",
    "BlockRuleProposal",
    "ObserveEnforceResult",
    "propose_block_rules",
]
