"""Join runtime enforcement signals to vulnerability findings.

Correlates proxy/gateway blocked and authorized tool calls (plus optional
scan-local runtime incident feedback) with finding rows so triage surfaces
``static`` vs ``observed`` vs ``blocked`` honestly instead of implying runtime
causality from static reachability alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

RUNTIME_STATE_STATIC = "static"
RUNTIME_STATE_OBSERVED = "observed"
RUNTIME_STATE_BLOCKED = "blocked"
RUNTIME_STATE_REPLAY_ONLY = "replay_only"


@dataclass
class RuntimeEvidenceIndex:
    """Tenant-scoped runtime events indexed for finding correlation."""

    blocked: list[dict[str, Any]] = field(default_factory=list)
    observed: list[dict[str, Any]] = field(default_factory=list)


def build_tenant_runtime_evidence_index(tenant_id: str) -> RuntimeEvidenceIndex:
    """Load recent proxy/gateway alerts for a tenant into a correlation index."""
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    index = RuntimeEvidenceIndex()
    for alert in _load_proxy_alerts(tenant_id):
        if not isinstance(alert, dict):
            continue
        action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "").lower()
        effective = str(alert.get("effective_decision") or alert.get("decision") or "").lower()
        if action in {"blocked", "block", "deny", "denied"} or effective in {"block", "blocked", "deny", "denied"}:
            index.blocked.append(_normalize_runtime_event(alert, state=RUNTIME_STATE_BLOCKED))
        elif action in {"allowed", "allow", "permit", "authorized"} or effective in {"allow", "allowed", "permit"}:
            index.observed.append(_normalize_runtime_event(alert, state=RUNTIME_STATE_OBSERVED))
        elif (
            str(alert.get("detector") or "").lower() in {"policy", "firewall", "dlp"}
            and str(alert.get("outcome") or "").lower() == "blocked"
        ):
            index.blocked.append(_normalize_runtime_event(alert, state=RUNTIME_STATE_BLOCKED))
    return index


def _normalize_runtime_event(alert: dict[str, Any], *, state: str) -> dict[str, Any]:
    agent = ""
    for key in ("agent_name", "agent", "source_agent", "source_id"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            agent = value.strip()
            break
    tool = ""
    for key in ("tool_name", "tool", "upstream", "target"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            tool = value.strip()
            break
    ts = alert.get("timestamp") or alert.get("event_timestamp") or alert.get("received_at") or ""
    return {
        "state": state,
        "agent": agent,
        "tool": tool,
        "timestamp": str(ts),
        "reason_code": str(alert.get("reason_code") or alert.get("policy_source") or alert.get("detector") or ""),
        "source": "proxy_alert",
    }


def _incident_records_to_events(records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw in records:
        if not isinstance(raw, Mapping):
            continue
        kind = str(raw.get("kind") or "").strip()
        state = RUNTIME_STATE_BLOCKED if kind == "kill_switch" else RUNTIME_STATE_OBSERVED
        for label in raw.get("observed_tool_labels") or []:
            if isinstance(label, str) and label.strip():
                events.append(
                    {
                        "state": state,
                        "agent": str(raw.get("agent_id") or ""),
                        "tool": label.strip(),
                        "timestamp": str(raw.get("observed_at") or ""),
                        "reason_code": kind or "runtime_incident",
                        "source": "runtime_incident_feedback",
                    }
                )
    return events


def _row_agents(row: Mapping[str, Any]) -> set[str]:
    agents: set[str] = set()
    for key in ("affected_agents", "agents"):
        value = row.get(key)
        if isinstance(value, list):
            agents.update(str(item).strip().lower() for item in value if str(item).strip())
    return agents


def _row_tools(row: Mapping[str, Any]) -> set[str]:
    tools: set[str] = set()
    for key in ("exposed_tools", "reachable_tools", "phantom_tools"):
        value = row.get(key)
        if isinstance(value, list):
            tools.update(str(item).strip().lower() for item in value if str(item).strip())
    return tools


def _event_matches_row(row: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    agents = _row_agents(row)
    tools = _row_tools(row)
    event_agent = str(event.get("agent") or "").strip().lower()
    event_tool = str(event.get("tool") or "").strip().lower()
    if event_agent and agents and event_agent not in agents:
        return False
    if event_tool and tools and event_tool not in tools:
        return False
    return bool((event_agent and agents) or (event_tool and tools))


def attach_runtime_evidence_to_finding(
    row: dict[str, Any],
    index: RuntimeEvidenceIndex | None,
    *,
    incidents: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach ``runtime_evidence`` summary to a finding row (in-place)."""
    events: list[dict[str, Any]] = []
    if index is not None:
        events.extend(event for event in index.blocked if _event_matches_row(row, event))
        events.extend(event for event in index.observed if _event_matches_row(row, event))
    if incidents:
        events.extend(event for event in _incident_records_to_events(incidents) if _event_matches_row(row, event))

    blocked_count = sum(1 for event in events if event.get("state") == RUNTIME_STATE_BLOCKED)
    observed_count = sum(1 for event in events if event.get("state") == RUNTIME_STATE_OBSERVED)
    if blocked_count:
        state = RUNTIME_STATE_BLOCKED
    elif observed_count:
        state = RUNTIME_STATE_OBSERVED
    else:
        state = RUNTIME_STATE_STATIC

    row["runtime_evidence"] = {
        "state": state,
        "blocked_count": blocked_count,
        "observed_count": observed_count,
        "events": events[:8],
    }
    return row


def compliance_tags_from_finding_row(row: Mapping[str, Any]) -> list[str]:
    """Flatten framework control tags already present on a finding row."""
    from agent_bom.compliance_utils import framework_qualified_tags_from_row

    return framework_qualified_tags_from_row(row)


__all__ = [
    "RUNTIME_STATE_BLOCKED",
    "RUNTIME_STATE_OBSERVED",
    "RUNTIME_STATE_REPLAY_ONLY",
    "RUNTIME_STATE_STATIC",
    "RuntimeEvidenceIndex",
    "attach_runtime_evidence_to_finding",
    "build_tenant_runtime_evidence_index",
    "compliance_tags_from_finding_row",
]
