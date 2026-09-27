"""One agent population for the scanned estate.

Every surface that lists or counts a tenant's scanned agents reads this helper,
so a project rescanned N times is one agent everywhere rather than N rows in one
place and one node in another.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

AGENT_COUNT_DEFINITION = "distinct canonical agent identities in the tenant's completed scans (latest observation wins)"


def agent_identity_key(agent: dict[str, Any]) -> str | None:
    """Canonical identity of a serialized agent; ``None`` when it carries none."""
    canonical = agent.get("canonical_id") or agent.get("stable_id")
    return str(canonical) if canonical else None


def scanned_estate_agents(jobs: Iterable[Any]) -> list[dict[str, Any]]:
    """Latest scan's observation of each canonical agent across completed jobs.

    A newer scan replaces an older scan's rows for the same canonical id; rows
    within one scan are all kept (they are distinct occurrences). Rows without
    identity evidence are never merged by name. Batch parents are skipped
    because their children already contribute the same agents. Order is
    first-seen, so pagination stays stable across rescans.
    """
    latest: dict[str, tuple[str, int, list[dict[str, Any]]]] = {}
    order: list[tuple[str | None, dict[str, Any] | None]] = []
    for job_index, job in enumerate(jobs):
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
            if key is None:
                order.append((None, agent))
                continue
            prior = latest.get(key)
            if prior is None:
                order.append((key, None))
                latest[key] = (stamp, job_index, [agent])
            elif prior[1] == job_index:
                prior[2].append(agent)
            elif stamp >= prior[0]:
                latest[key] = (stamp, job_index, [agent])
    rows: list[dict[str, Any]] = []
    for key, anonymous in order:
        if key is None:
            if anonymous is not None:
                rows.append(anonymous)
        else:
            rows.extend(latest[key][2])
    return rows


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
