"""One agent population for the scanned estate.

Every surface that lists or counts a tenant's scanned agents reads this helper,
so a project rescanned N times is one agent everywhere rather than N rows in one
place and one node in another.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

AGENT_COUNT_DEFINITION = "distinct canonical agent identities in the tenant's completed scans (latest observation wins)"


def agent_identity_key(agent: dict[str, Any]) -> str:
    canonical = agent.get("canonical_id") or agent.get("stable_id")
    if canonical:
        return str(canonical)
    return f"{agent.get('agent_type') or ''}|{agent.get('name') or ''}|{agent.get('config_path') or ''}"


def scanned_estate_agents(jobs: Iterable[Any]) -> list[dict[str, Any]]:
    """Latest observation of each canonical agent across completed scan jobs.

    Batch parents are skipped because their children already contribute the
    same agents. Order is first-seen, so pagination stays stable as rescans
    replace an agent's payload with its newest observation.
    """
    latest: dict[str, tuple[str, dict[str, Any]]] = {}
    order: list[str] = []
    for job in jobs:
        if getattr(job, "child_job_ids", None):
            continue
        result = getattr(job, "result", None)
        if not isinstance(result, dict):
            continue
        stamp = str(getattr(job, "completed_at", None) or getattr(job, "created_at", None) or "")
        for agent in result.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            key = agent_identity_key(agent)
            prior = latest.get(key)
            if prior is None:
                order.append(key)
            if prior is None or stamp >= prior[0]:
                latest[key] = (stamp, agent)
    return [latest[key][1] for key in order]


def classify_agent_payload(agent: dict[str, Any]) -> str:
    """Dict twin of ``models.classify_agent_kind`` for serialized report agents."""
    if str(agent.get("agent_type") or agent.get("type") or "custom") != "custom":
        return "client"
    if str(agent.get("name") or "").startswith(("sbom:", "image:")):
        return "synthetic"
    return "background"


def count_agent_payloads_by_class(agents: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"client": 0, "background": 0}
    for agent in agents:
        kind = classify_agent_payload(agent)
        if kind in counts:
            counts[kind] += 1
    return counts
