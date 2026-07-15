"""Join FinOps spend + budgets to the accountable human owner (#3909).

FinOps budgets scope to agent / tenant / cost-center (see
:mod:`agent_bom.api.cost_store`). This module adds the *ownership* join: it
resolves the accountable owner (and governing blueprint / "workflow") of an
agent from the persisted governance blueprints
(:mod:`agent_bom.api.blueprint_store`), then reuses the existing cost store to

- enforce an owner-scoped (or owner+workflow) spend cap at the same
  pre-invocation gateway point that already enforces tenant/agent caps, and
- report spend grouped by accountable owner (owner-level cost / ROI).

Owner spend is the aggregate spend of every agent the owner governs, summed from
the per-agent spend the cost store already tracks — no new per-call column is
required, so ingest paths are unchanged and pre-existing spend attributes
correctly the moment a governing blueprint is approved.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.blueprint_store import build_agent_owner_index, get_blueprint_store
from agent_bom.api.cost_store import CostBudget, CostStore, LLMCostRecord, check_owner_budget_enforcement, summarize_by_owner


def agent_owner_index(tenant_id: str) -> dict[str, tuple[str, str]]:
    """Return ``agent -> (owner, workflow_blueprint_id)`` for the active tenant."""
    return build_agent_owner_index(get_blueprint_store(), tenant_id)


def resolve_owner_for_agent(tenant_id: str, agent: str) -> tuple[str, str]:
    """Resolve one agent's accountable ``(owner, workflow)`` from its blueprint.

    Returns ``("", "")`` when no approved blueprint governs the agent.
    """
    if not agent:
        return "", ""
    return agent_owner_index(tenant_id).get(agent, ("", ""))


def _flat_agent_owner(index: dict[str, tuple[str, str]]) -> dict[str, str]:
    return {agent: owner for agent, (owner, _workflow) in index.items()}


def owner_spend(store: CostStore, index: dict[str, tuple[str, str]], tenant_id: str, owner: str, workflow: str = "") -> float:
    """Aggregate spend across every agent the owner governs.

    When ``workflow`` is set, only agents governed by that specific blueprint are
    summed, so an owner+workflow budget caps a single governing blueprint.
    """
    if not owner:
        return 0.0
    total = 0.0
    for agent, (agent_owner, agent_workflow) in index.items():
        if agent_owner != owner:
            continue
        if workflow and agent_workflow != workflow:
            continue
        total += store.total_spend(tenant_id, agent=agent)
    return round(total, 6)


def enforce_owner_budget(store: CostStore, tenant_id: str, agent: str) -> tuple[bool, CostBudget | None, float, str, str]:
    """Pre-invocation owner-budget check for one agent's call (#3909).

    Resolves the agent's accountable owner (+ governing workflow) from the
    blueprints, computes the owner's aggregate spend, and asks the cost store
    whether an enforce-mode owner budget is exceeded. Returns
    ``(blocked, budget, spend, owner, workflow)``. A no-owner agent, or an owner
    with no enforce budget, never blocks.
    """
    index = agent_owner_index(tenant_id)
    owner, workflow = index.get(agent, ("", ""))
    if not owner:
        return False, None, 0.0, "", ""
    spend = owner_spend(store, index, tenant_id, owner, workflow)
    blocked, budget = check_owner_budget_enforcement(store, tenant_id, owner, workflow, spend)
    # When the matched budget is owner-wide (no workflow) recompute spend across
    # the owner's full agent set so the reported figure matches the cap's scope.
    if budget is not None and not budget.workflow and workflow:
        spend = owner_spend(store, index, tenant_id, owner, "")
        blocked = budget.mode == "enforce" and spend >= budget.limit_usd
    return blocked, budget, spend, owner, workflow


def owner_cost_report(store: CostStore, tenant_id: str, records: list[LLMCostRecord]) -> dict[str, Any]:
    """Owner-attributed spend rollup for a record list (owner-level cost / ROI)."""
    index = agent_owner_index(tenant_id)
    return summarize_by_owner(records, _flat_agent_owner(index))


__all__ = [
    "agent_owner_index",
    "enforce_owner_budget",
    "owner_cost_report",
    "owner_spend",
    "resolve_owner_for_agent",
]
