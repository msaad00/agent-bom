"""One-paragraph executive headline shared by the HTML report and the compliance narrative.

Leadership reads the headline; engineers read the drill beneath it. Both must
come from the same rows, so this module takes plain finding rows and never
invents an owner, an SLA or an exploitation claim: a missing owner reads
"unassigned", a missing SLA reads "no SLA set", and agent reach means a recorded
path from an agent, not proof of exploitation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

from agent_bom.core.severity import severity_band_rank

EXECUTIVE_HEADLINE_BOUNDARY = (
    "This summary describes scan evidence; it is not a compliance certification or audit opinion. "
    "A recorded agent path does not by itself prove exploitation."
)


@dataclass
class HeadlineRisk:
    id: str
    title: str
    severity: str
    risk_score: float | None
    affected_agents: list[str] = field(default_factory=list)
    owner: str | None = None
    sla_due_at: str | None = None


@dataclass
class ExecutiveHeadline:
    summary: str
    top_risks: list[HeadlineRisk] = field(default_factory=list)
    claim_boundary: str = EXECUTIVE_HEADLINE_BOUNDARY


def _as_float(value: object) -> float | None:
    if value is None or isinstance(value, bool) or value == "":
        return None
    try:
        score = float(value) if isinstance(value, (int, float, str)) else None
    except ValueError:
        return None
    # Producers that never score a finding emit 0; that is "unscored", not "no risk".
    return score if score is not None and score > 0 else None


def _owner(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _sla_date(value: object) -> str | None:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, str) and value.strip():
        return value.strip()[:10]
    return None


def _risk_from_row(row: Mapping[str, object]) -> HeadlineRisk:
    agents = row.get("affected_agents")
    return HeadlineRisk(
        id=str(row.get("id") or "Unavailable"),
        title=str(row.get("title") or row.get("id") or "Unavailable"),
        severity=str(row.get("severity") or "unknown").lower(),
        risk_score=_as_float(row.get("risk_score")),
        affected_agents=[str(name) for name in agents] if isinstance(agents, (list, tuple, set)) else [],
        owner=_owner(row.get("owner")),
        sla_due_at=_sla_date(row.get("sla_due_at")),
    )


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _risk_sentence(risk: HeadlineRisk) -> str:
    reach = f"reaches {', '.join(risk.affected_agents[:3])}" if risk.affected_agents else "reaches no recorded agent"
    if len(risk.affected_agents) > 3:
        reach += f" and {len(risk.affected_agents) - 3} more"
    owner = f"owner {risk.owner}" if risk.owner else "owner unassigned"
    sla = f"SLA due {risk.sla_due_at}" if risk.sla_due_at else "no SLA set"
    score = f"risk {risk.risk_score:.1f}/10" if risk.risk_score is not None else "risk unscored"
    return f"{risk.title} ({risk.severity}, {score}) {reach}; {owner}; {sla}."


def build_executive_headline(rows: Iterable[Mapping[str, object]], *, limit: int = 3) -> ExecutiveHeadline:
    """Build the headline from finding rows.

    Each row may carry ``id``, ``title``, ``severity``, ``risk_score``,
    ``affected_agents``, ``owner`` and ``sla_due_at``; anything missing is
    reported as missing, never filled in.
    """
    risks = [_risk_from_row(row) for row in rows]
    if not risks:
        return ExecutiveHeadline(
            summary=(
                "No findings were recorded in this scan's evidence scope. "
                "This is not a claim that unscanned or unavailable sources are clean."
            )
        )

    # Severity first: an unscored critical must not rank below a scored medium.
    risks.sort(key=lambda risk: (severity_band_rank(risk.severity), -(risk.risk_score or 0.0), risk.id))
    top = risks[:limit]
    total = len(risks)
    critical = sum(1 for risk in risks if risk.severity == "critical")
    high = sum(1 for risk in risks if risk.severity == "high")
    reaching = sum(1 for risk in risks if risk.affected_agents)
    unassigned = sum(1 for risk in top if risk.owner is None)

    sentences = [
        f"{_plural(total, 'finding')} ({critical} critical, {high} high).",
        f"{reaching} of {total} findings reach at least one AI agent through a recorded path.",
        f"Top {_plural(len(top), 'risk')}: " + " ".join(f"{index}. {_risk_sentence(risk)}" for index, risk in enumerate(top, start=1)),
    ]
    if unassigned:
        sentences.append(f"{unassigned} of the top {len(top)} {'has' if unassigned == 1 else 'have'} no owner.")
    return ExecutiveHeadline(summary=" ".join(sentences), top_risks=top)


__all__ = ["EXECUTIVE_HEADLINE_BOUNDARY", "ExecutiveHeadline", "HeadlineRisk", "build_executive_headline"]
