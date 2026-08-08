"""Seed AI-system blueprints and LLM spend for the demo estate.

Same gap the fleet/runtime seed already closed for the AI BOM page: the
governance and cost surfaces read stores that the graph and findings seeds never
touch. On a fully populated demo estate they returned

    /v1/governance/blueprints  -> {"count": 0, "blueprints": []}
    /v1/observability/costs    -> {"total_calls": 1}

so both pages rendered as empty shells on an estate with thousands of assets,
which reads as a broken product rather than an unconfigured one.

Every write here is idempotent and tenant-scoped: seeding runs on each boot and
must not duplicate rows or trample an operator's own blueprints.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

_logger = logging.getLogger(__name__)

# Marker on every seeded cost row, so a rollover top-up can tell the demo's own
# spend from an operator's without touching theirs.
_DEMO_CALL_ID_PREFIX = "demo-"

# Trailing days of spend the cost/forecast surfaces read.
_SPEND_WINDOW_DAYS = 14

# Weekday shape (Mon..Sun): real LLM spend dips over the weekend. Deterministic
# per absolute date, so a day written by a backfill and a day written by a
# rollover top-up agree on what that date cost.
_WEEKDAY_SPEND_SCALE: tuple[float, ...] = (1.0, 1.02, 1.05, 1.03, 0.98, 0.62, 0.48)

# Blueprints mirror the archetypes the runtime blueprint library already ships,
# so a demo viewer sees the same vocabulary the product uses everywhere else.
_BLUEPRINTS: tuple[dict[str, Any], ...] = (
    {
        "id": "bp-clinical-summarization",
        "name": "Clinical Summarization Agent",
        "owner": "clinical-ai@northstar-health.example",
        "owner_type": "team",
        "description": "Summarizes encounter notes for clinician review. Human-in-the-loop before any chart write.",
        "status": "approved",
        "agents": ["clinical-summarizer"],
        "models": ["claude-opus-5", "gpt-5"],
        "tools": ["ehr.read_encounter", "terminology.lookup"],
        "datasets": ["encounters-deid"],
        "identities": ["svc-clinical-summarizer"],
        "guardrails": ["phi_redaction", "human_review_before_write", "no_outbound_network"],
    },
    {
        "id": "bp-claims-triage",
        "name": "Claims Triage Agent",
        "owner": "revenue-cycle@northstar-health.example",
        "owner_type": "team",
        "description": "Routes and scores inbound claims. Read-only against the claims warehouse.",
        "status": "approved",
        "agents": ["claims-triage"],
        "models": ["claude-sonnet-5"],
        "tools": ["claims.search", "policy.lookup"],
        "datasets": ["claims-2026"],
        "identities": ["svc-claims-triage"],
        "guardrails": ["read_only_warehouse", "spend_cap_enforced"],
    },
    {
        "id": "bp-prior-auth",
        "name": "Prior Authorization Assistant",
        "owner": "utilization-mgmt@northstar-health.example",
        "owner_type": "team",
        "description": "Drafts prior-auth packets. Every submission is approval-gated.",
        "status": "pending",
        "agents": ["prior-auth-drafter"],
        "models": ["claude-opus-5"],
        "tools": ["payer.submit_draft", "ehr.read_encounter"],
        "datasets": ["payer-policies"],
        "identities": ["svc-prior-auth"],
        "guardrails": ["approval_gated_submission", "phi_redaction"],
    },
    {
        "id": "bp-devsecops-copilot",
        "name": "DevSecOps Copilot",
        "owner": "platform-security@northstar-health.example",
        "owner_type": "team",
        "description": "Repo-scoped remediation copilot. No production credentials.",
        "status": "approved",
        "agents": ["devsecops-copilot"],
        "models": ["claude-sonnet-5"],
        "tools": ["repo.read", "repo.open_pull_request", "scanner.query"],
        "datasets": [],
        "identities": ["svc-devsecops-copilot"],
        "guardrails": ["no_production_credentials", "pull_request_only"],
    },
    {
        "id": "bp-patient-chat",
        "name": "Patient Intake Chat",
        "owner": "digital-front-door@northstar-health.example",
        "owner_type": "team",
        "description": "Public-facing intake assistant. Draft — not yet approved for production traffic.",
        "status": "draft",
        "agents": ["patient-intake-chat"],
        "models": ["claude-haiku-4-5"],
        "tools": ["scheduling.availability"],
        "datasets": [],
        "identities": ["svc-patient-intake"],
        "guardrails": ["no_phi_access", "prompt_injection_filter"],
    },
)

# DAILY token volumes per agent/model, spread across providers and cost centers
# so chargeback and forecast have more than one point to draw.
#
# These are deliberately enterprise-scale rather than token-sized: a health
# system running claims triage and clinical summarization at production volume
# spends five figures a month on inference. Windowed totals divided across the
# period produced a demo reading ~$18, which undersells the cost surface to the
# exact audience — leadership — that the page exists for.
_SPEND: tuple[tuple[str, str, str, str, int, int], ...] = (
    ("clinical-summarizer", "anthropic", "claude-opus-5", "clinical-ai", 12_400_000, 1_380_000),
    ("clinical-summarizer", "openai", "gpt-5", "clinical-ai", 3_100_000, 402_000),
    ("claims-triage", "anthropic", "claude-sonnet-5", "revenue-cycle", 41_800_000, 3_120_000),
    ("prior-auth-drafter", "anthropic", "claude-opus-5", "utilization-mgmt", 6_050_000, 1_140_000),
    ("devsecops-copilot", "anthropic", "claude-sonnet-5", "platform-security", 18_300_000, 3_240_000),
    ("patient-intake-chat", "anthropic", "claude-haiku-4-5", "digital-front-door", 2_460_000, 318_000),
)

# Rough blended $/1M tokens by model, used only to price the synthetic spend.
_PRICE_PER_MILLION: dict[str, tuple[float, float]] = {
    "claude-opus-5": (15.0, 75.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "gpt-5": (10.0, 30.0),
}


def _price(model: str, input_tokens: int, output_tokens: int) -> float:
    rate_in, rate_out = _PRICE_PER_MILLION.get(model, (3.0, 15.0))
    return round(input_tokens / 1_000_000 * rate_in + output_tokens / 1_000_000 * rate_out, 2)


def seed_showcase_governance_and_cost(*, tenant_id: str, now: datetime | None = None) -> dict[str, int]:
    """Seed blueprints and priced LLM calls. Idempotent per tenant.

    ``now`` overrides the UTC clock so the trailing spend window is testable
    across a day rollover without a frozen clock.
    """
    return {
        "blueprints": _seed_blueprints(tenant_id=tenant_id),
        "cost_records": _seed_cost_records(tenant_id=tenant_id, now=now),
    }


def _seed_blueprints(*, tenant_id: str) -> int:
    from agent_bom.api.blueprint_store import (
        Blueprint,
        BlueprintComposition,
        BlueprintVersion,
        get_blueprint_store,
    )

    store = get_blueprint_store()
    # An operator's own blueprints must never be joined by demo rows.
    if store.list_blueprints(tenant_id, limit=1).blueprints:
        return 0

    now = datetime.now(timezone.utc)
    seeded = 0
    for offset, spec in enumerate(_BLUEPRINTS):
        created = (now - timedelta(days=45 - offset * 7)).isoformat()
        status = str(spec["status"])
        approved = status == "approved"
        store.put_blueprint(
            Blueprint(
                blueprint_id=str(spec["id"]),
                tenant_id=tenant_id,
                name=str(spec["name"]),
                owner=str(spec["owner"]),
                owner_type=str(spec["owner_type"]),
                description=str(spec["description"]),
                created_at=created,
                updated_at=created,
                current_version=1 if approved else 0,
                latest_version=1,
                approval_status=status,
                seeded_from="demo_estate",
            )
        )
        store.put_version(
            BlueprintVersion(
                version_id=f"{spec['id']}-v1",
                blueprint_id=str(spec["id"]),
                tenant_id=tenant_id,
                version=1,
                status=status,
                composition=BlueprintComposition(
                    agents=list(spec["agents"]),
                    models=list(spec["models"]),
                    tools=list(spec["tools"]),
                    datasets=list(spec["datasets"]),
                    identities=list(spec["identities"]),
                    owners=[str(spec["owner"])],
                    guardrails=list(spec["guardrails"]),
                ),
                created_at=created,
                created_by=str(spec["owner"]),
                submitted_at=created if status != "draft" else "",
                submitted_by=str(spec["owner"]) if status != "draft" else "",
                decided_at=created if approved else "",
                # An approved version is never orphaned — it carries its approver.
                approver="ciso@northstar-health.example" if approved else "",
                decision_note="Reviewed against the AI governance standard." if approved else "",
                seeded_from="demo_estate",
            )
        )
        seeded += 1
    return seeded


def _seed_cost_records(*, tenant_id: str, now: datetime | None = None) -> int:
    """Seed a trailing window of priced LLM calls, topping up on a day rollover.

    The cost page and the gateway ``calls_today`` KPI window on
    ``[UTC midnight, request time]``. Seeding once and never again left the
    newest record stamped with the boot day, so those surfaces read 0 from the
    first midnight onward and — unlike the gateway feed, which the bootstrap
    loop re-seeds — never recovered, because the old guard treated "any records
    exist" as "already seeded". Days are keyed by absolute date, so a later pass
    inserts only the missing ones and never rewrites a day already stored.
    """
    from agent_bom.api.cost_store import LLMCostRecord, get_cost_store

    store = get_cost_store()
    now = now or datetime.now(timezone.utc)

    existing = store.list_records(tenant_id, limit=5000)
    demo_records = [record for record in existing if record.call_id.startswith(_DEMO_CALL_ID_PREFIX)]
    # An operator's own spend must never be joined by demo rows.
    if existing and not demo_records:
        return 0
    # Keyed on the stored date rather than the id, so days written by an earlier
    # relative-index format are still recognised as covered and not duplicated.
    covered_days = {record.observed_at[:10] for record in demo_records}

    seeded = 0
    for day in range(_SPEND_WINDOW_DAYS):
        observed_at = now - timedelta(days=_SPEND_WINDOW_DAYS - 1 - day)
        date_key = observed_at.date().isoformat()
        if date_key in covered_days:
            continue
        observed = observed_at.isoformat()
        # Ramp older days slightly so burn-rate has a slope to fit and the
        # forecast is not extrapolating from a flat line. The weekday shape
        # carries that variation once the ramp has aged out of the window and
        # every day is being topped up at full scale.
        scale = ((day + 8) / 21) * _WEEKDAY_SPEND_SCALE[observed_at.weekday()]
        for agent, provider, model, cost_center, in_tokens, out_tokens in _SPEND:
            daily_in = int(in_tokens * scale)
            daily_out = int(out_tokens * scale)
            if daily_in <= 0:
                continue
            store.record_cost(
                LLMCostRecord(
                    tenant_id=tenant_id,
                    # The model belongs in the key: one agent legitimately calls
                    # more than one model (clinical-summarizer uses both), and
                    # keying on agent+day alone made the second overwrite the
                    # first, silently dropping a whole provider's spend. The
                    # absolute date — not a relative index — keys the day, so a
                    # rollover top-up inserts a new row instead of colliding
                    # with an id the store would ignore.
                    call_id=f"{_DEMO_CALL_ID_PREFIX}{agent}-{model}-{date_key}",
                    agent=agent,
                    session_id=f"demo-session-{agent}-{model}-{date_key}",
                    provider=provider,
                    model=model,
                    input_tokens=daily_in,
                    output_tokens=daily_out,
                    cost_usd=_price(model, daily_in, daily_out),
                    priced=True,
                    observed_at=observed,
                    cost_center=cost_center,
                    allocation_tags={"business_unit": cost_center, "environment": "production"},
                )
            )
            seeded += 1
    return seeded
