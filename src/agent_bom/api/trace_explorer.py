"""Trace explorer payload builder — runtime events joined to findings (#3608).

Fuses gateway/proxy feed events and runtime observations into a Langfuse-style
session tree where each tool-call span links to correlated findings (CVE,
compliance controls, policy block reason).
"""

from __future__ import annotations

from typing import Any, Mapping


def _norm(value: object) -> str:
    return str(value or "").strip().lower()


def correlate_findings(
    *,
    agent: str,
    tool: str,
    findings: list[Mapping[str, Any]],
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Return findings whose agent/tool exposure overlaps this runtime event."""
    agent_key = _norm(agent)
    tool_key = _norm(tool)
    if not agent_key and not tool_key:
        return []

    matched: list[dict[str, Any]] = []
    for row in findings:
        if not isinstance(row, Mapping):
            continue
        agents = {_norm(a) for a in (row.get("affected_agents") or []) if _norm(a)}
        tools = set()
        for key in ("exposed_tools", "reachable_tools", "phantom_tools"):
            tools.update(_norm(t) for t in (row.get(key) or []) if _norm(t))
        if agent_key and agents and agent_key not in agents:
            continue
        if tool_key and tools and tool_key not in tools:
            continue
        if not agents and not tools:
            continue
        matched.append(
            {
                "finding_id": row.get("id") or row.get("vulnerability_id"),
                "vulnerability_id": row.get("vulnerability_id") or row.get("cve_id"),
                "severity": row.get("severity"),
                "risk_score": row.get("risk_score"),
                "effective_reach_band": row.get("effective_reach_band"),
                "framework_tags": row.get("framework_tags") or [],
                "runtime_evidence": row.get("runtime_evidence"),
                "policy_state": (row.get("runtime_evidence") or {}).get("state"),
            }
        )
        if len(matched) >= limit:
            break
    return matched


def _span_from_feed_event(event: Mapping[str, Any], *, findings: list[Mapping[str, Any]]) -> dict[str, Any]:
    action = str(event.get("action_type") or "")
    agent = str(event.get("agent") or "")
    tool = str(event.get("target") or "")
    blocked = action == "tool_call_blocked"
    return {
        "span_id": f"{event.get('ts')}:{agent}:{tool}",
        "timestamp": event.get("ts"),
        "agent": agent,
        "tool": tool,
        "action_type": action,
        "verdict": "blocked" if blocked else ("observed" if action == "tool_call_authorized" else action),
        "detail": event.get("detail"),
        "shadow": bool(event.get("shadow")),
        "source": event.get("source"),
        "linked_findings": correlate_findings(agent=agent, tool=tool, findings=findings),
        "compliance_controls": sorted(
            {
                tag
                for finding in correlate_findings(agent=agent, tool=tool, findings=findings, limit=8)
                for tag in (finding.get("framework_tags") or [])
            }
        ),
    }


def _span_from_observation(obs: Mapping[str, Any], *, findings: list[Mapping[str, Any]]) -> dict[str, Any]:
    agent = str(obs.get("agent_name") or "")
    tool = str(obs.get("tool_name") or "")
    verdict = str(obs.get("verdict") or "observed")
    return {
        "span_id": str(obs.get("observation_id") or obs.get("span_id") or ""),
        "timestamp": obs.get("observed_at"),
        "agent": agent,
        "tool": tool,
        "action_type": str(obs.get("event_type") or "runtime_observation"),
        "verdict": verdict,
        "detail": str((obs.get("summary") or {}).get("message") or obs.get("event_type") or ""),
        "shadow": False,
        "source": obs.get("source") or "runtime_store",
        "trace_id": obs.get("trace_id"),
        "session_id": obs.get("session_id"),
        "linked_findings": correlate_findings(agent=agent, tool=tool, findings=findings),
        "compliance_controls": sorted(
            {
                tag
                for finding in correlate_findings(agent=agent, tool=tool, findings=findings, limit=8)
                for tag in (finding.get("framework_tags") or [])
            }
        ),
    }


def build_trace_explorer_payload(
    *,
    tenant_id: str,
    feed_events: list[Mapping[str, Any]],
    findings: list[Mapping[str, Any]],
    sessions: list[Mapping[str, Any]],
    observations: list[Mapping[str, Any]],
    limit: int = 100,
) -> dict[str, Any]:
    """Build session-grouped trace explorer tree for the UI."""
    session_map: dict[str, dict[str, Any]] = {}

    def _ensure_session(session_id: str, *, agent: str = "", trace_id: str = "") -> dict[str, Any]:
        if session_id not in session_map:
            session_map[session_id] = {
                "session_id": session_id,
                "agent": agent,
                "trace_id": trace_id,
                "spans": [],
                "blocked_count": 0,
                "observed_count": 0,
            }
        return session_map[session_id]

    for event in feed_events[:limit]:
        agent = str(event.get("agent") or "unknown")
        session_id = f"feed:{agent}"
        session = _ensure_session(session_id, agent=agent)
        span = _span_from_feed_event(event, findings=findings)
        session["spans"].append(span)
        if span["verdict"] == "blocked":
            session["blocked_count"] += 1
        else:
            session["observed_count"] += 1

    for obs in observations[:limit]:
        session_id = str(obs.get("session_id") or f"obs:{obs.get('trace_id') or obs.get('agent_name') or 'unknown'}")
        session = _ensure_session(
            session_id,
            agent=str(obs.get("agent_name") or ""),
            trace_id=str(obs.get("trace_id") or ""),
        )
        span = _span_from_observation(obs, findings=findings)
        session["spans"].append(span)
        if span["verdict"] == "blocked":
            session["blocked_count"] += 1
        else:
            session["observed_count"] += 1

    for raw_session in sessions:
        session_id = str(raw_session.get("session_id") or "")
        if not session_id:
            continue
        session = _ensure_session(
            session_id,
            agent=str(raw_session.get("agent_name") or ""),
            trace_id=str(raw_session.get("trace_id") or ""),
        )
        session.setdefault("first_seen", raw_session.get("first_seen"))
        session.setdefault("last_seen", raw_session.get("last_seen"))
        session.setdefault("observation_count", raw_session.get("observation_count"))

    sessions_out = sorted(session_map.values(), key=lambda row: str(row.get("last_seen") or row.get("session_id")), reverse=True)
    for session in sessions_out:
        session["spans"].sort(key=lambda span: str(span.get("timestamp") or ""), reverse=True)

    total_blocked = sum(int(s.get("blocked_count") or 0) for s in sessions_out)
    total_spans = sum(len(s.get("spans") or []) for s in sessions_out)

    return {
        "schema_version": "runtime.trace_explorer.v1",
        "tenant_id": tenant_id,
        "session_count": len(sessions_out),
        "span_count": total_spans,
        "blocked_count": total_blocked,
        "sessions": sessions_out,
    }


__all__ = ["build_trace_explorer_payload", "correlate_findings"]
