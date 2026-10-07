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

_FIELD_TO_FRAMEWORK = {
    "owasp_tags": "owasp_llm",
    "atlas_tags": "atlas",
    "nist_ai_rmf_tags": "nist_ai_rmf",
    "owasp_mcp_tags": "owasp_mcp",
    "owasp_agentic_tags": "owasp_agentic",
    "eu_ai_act_tags": "eu_ai_act",
    "nist_csf_tags": "nist_csf",
    "iso_27001_tags": "iso_27001",
    "soc2_tags": "soc2",
    "cis_tags": "cis",
    "cmmc_tags": "cmmc",
    "nist_800_53_tags": "nist_800_53",
    "fedramp_tags": "fedramp",
    "pci_dss_tags": "pci_dss",
    "attack_tags": "attack",
}


@dataclass
class _RuntimeMatches:
    blocked_count: int = 0
    observed_count: int = 0
    examples: list[tuple[int, dict[str, Any]]] = field(default_factory=list)


@dataclass
class RuntimeEvidenceIndex:
    """Tenant-scoped event snapshot, indexed by exact agent and tool identity.

    Counts retain every event; at most eight examples per identity are retained
    for bounded finding summaries. Build a new snapshot when evidence changes.
    """

    blocked: list[dict[str, Any]] = field(default_factory=list)
    observed: list[dict[str, Any]] = field(default_factory=list)
    _matches: dict[tuple[str, str], _RuntimeMatches] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        for ordinal, event in enumerate((*self.blocked, *self.observed)):
            agent = str(event.get("agent") or "").strip()
            tool = str(event.get("tool") or "").strip()
            if not agent or not tool:
                continue
            match = self._matches.setdefault((agent, tool), _RuntimeMatches())
            match.blocked_count += event.get("state") == RUNTIME_STATE_BLOCKED
            match.observed_count += event.get("state") == RUNTIME_STATE_OBSERVED
            if len(match.examples) < 8:
                match.examples.append((ordinal, dict(event)))

    def matching(self, agents: set[str], tools: set[str]) -> _RuntimeMatches:
        result = _RuntimeMatches()
        for agent in agents:
            for tool in tools:
                match = self._matches.get((agent, tool))
                if match is not None:
                    result.blocked_count += match.blocked_count
                    result.observed_count += match.observed_count
                    result.examples.extend(match.examples)
        result.examples = sorted(result.examples, key=lambda item: item[0])[:8]
        return result


def build_incident_runtime_evidence_index(records: list[Mapping[str, Any]]) -> RuntimeEvidenceIndex:
    """Index a scan's incidents once, retaining their original source order."""
    return RuntimeEvidenceIndex(observed=_incident_records_to_events(records))


def build_tenant_runtime_evidence_index(tenant_id: str) -> RuntimeEvidenceIndex:
    """Load recent proxy/gateway alerts for a tenant into a correlation index."""
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    blocked: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    for alert in _load_proxy_alerts(tenant_id):
        if not isinstance(alert, dict):
            continue
        action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "").lower()
        effective = str(alert.get("effective_decision") or alert.get("decision") or "").lower()
        if action in {"blocked", "block", "deny", "denied"} or effective in {"block", "blocked", "deny", "denied"}:
            blocked.append(_normalize_runtime_event(alert, state=RUNTIME_STATE_BLOCKED))
        elif action in {"allowed", "allow", "permit", "authorized"} or effective in {"allow", "allowed", "permit"}:
            observed.append(_normalize_runtime_event(alert, state=RUNTIME_STATE_OBSERVED))
        elif (
            str(alert.get("detector") or "").lower() in {"policy", "firewall", "dlp"}
            and str(alert.get("outcome") or "").lower() == "blocked"
        ):
            blocked.append(_normalize_runtime_event(alert, state=RUNTIME_STATE_BLOCKED))
    return RuntimeEvidenceIndex(blocked=blocked, observed=observed)


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
            agents.update(item.strip() for item in value if isinstance(item, str) and item.strip())
    return agents


def _row_tools(row: Mapping[str, Any]) -> set[str]:
    tools: set[str] = set()
    for key in ("exposed_tools", "reachable_tools", "phantom_tools"):
        value = row.get(key)
        if isinstance(value, list):
            tools.update(item.strip() for item in value if isinstance(item, str) and item.strip())
    return tools


def attach_runtime_evidence_to_finding(
    row: dict[str, Any],
    index: RuntimeEvidenceIndex | None,
    *,
    incidents: list[Mapping[str, Any]] | None = None,
    incident_index: RuntimeEvidenceIndex | None = None,
) -> dict[str, Any]:
    """Attach ``runtime_evidence`` summary to a finding row (in-place)."""
    agents, tools = _row_agents(row), _row_tools(row)
    events: list[dict[str, Any]] = []
    blocked_count = observed_count = 0
    if incident_index is None and incidents:
        incident_index = build_incident_runtime_evidence_index(incidents)
    for source in (index, incident_index):
        if source is None:
            continue
        match = source.matching(agents, tools)
        blocked_count += match.blocked_count
        observed_count += match.observed_count
        events.extend(event for _, event in match.examples[: 8 - len(events)])

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
    tags: list[str] = []
    seen: set[str] = set()

    def add(framework: str, control: object) -> None:
        control_text = str(control or "").strip()
        if not control_text:
            return
        value = control_text if ":" in control_text else f"{framework}:{control_text}"
        if value not in seen:
            seen.add(value)
            tags.append(value)

    raw = row.get("compliance_tags")
    if isinstance(raw, dict):
        for framework, values in sorted(raw.items()):
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for value in values:
                    add(str(framework), value)
    elif isinstance(raw, list):
        for value in raw:
            add("generic", value)

    for tag_field, framework in _FIELD_TO_FRAMEWORK.items():
        values = row.get(tag_field)
        if isinstance(values, list):
            for value in values:
                add(framework, value)

    controls = row.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict):
                add(str(control.get("framework") or "generic"), control.get("control") or control.get("id"))

    return sorted(tags)


__all__ = [
    "RUNTIME_STATE_BLOCKED",
    "RUNTIME_STATE_OBSERVED",
    "RUNTIME_STATE_REPLAY_ONLY",
    "RUNTIME_STATE_STATIC",
    "RuntimeEvidenceIndex",
    "attach_runtime_evidence_to_finding",
    "build_incident_runtime_evidence_index",
    "build_tenant_runtime_evidence_index",
    "compliance_tags_from_finding_row",
]
