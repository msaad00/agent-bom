"""Runtime → graph incident feedback (the feedback direction of the moat).

The *consume* direction of agent-bom's agentic moat projects static graph
reachability into the runtime gateway so it can pre-emptively block calls the
graph proves are reachable. This module closes the loop in the **feedback**
direction: runtime-observed risk — an agent was *seen* reaching a privileged or
credential node, tripping the lateral-movement correlator, or hitting the
kill-switch — is written out as durable, structured records so the **next**
scan's unified graph ingests OBSERVED behavior, not just static reachability.

Design invariants:

* **Default-off.** Emission is gated by an explicit sink path (constructor arg
  or ``AGENT_BOM_RUNTIME_FEEDBACK_PATH`` env). Absent a sink, every emit is a
  no-op and runtime behavior is byte-identical to today.
* **Fail-safe.** A sink that cannot be written (bad path, disk full, races) is
  logged at debug level and swallowed — it must never break a live relay.
* **Deterministic.** Records carry an injected timestamp (caller passes a clock
  value); this module never calls ``time.time()`` itself, so tests stay stable.
* **No network.** Records are appended to a local JSONL file only.
* **Sanitized.** Node ids / labels are sanitized on the way out so secrets and
  PII never reach the durable sink.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "runtime_incident_feedback.v1"

# Env var that turns the feedback sink on without code changes.
ENV_FEEDBACK_PATH = "AGENT_BOM_RUNTIME_FEEDBACK_PATH"


class IncidentKind(str, Enum):
    """Kind of runtime-observed risk being fed back into the graph."""

    REACHED_CREDENTIAL = "reached_credential"
    LATERAL_MOVEMENT = "lateral_movement"
    KILL_SWITCH = "kill_switch"


# How each incident kind projects onto the next-scan graph: the agent node gets
# an ``observed_<attr>`` flag, and (when an observed node id is present) an edge
# of the mapped relationship is drawn from the agent to that node.
_KIND_ATTRIBUTE: dict[str, str] = {
    IncidentKind.REACHED_CREDENTIAL.value: "observed_reached_credential",
    IncidentKind.LATERAL_MOVEMENT.value: "observed_lateral_movement",
    IncidentKind.KILL_SWITCH.value: "observed_kill_switch",
}


@dataclass
class RuntimeIncidentRecord:
    """A single runtime-observed incident, serializable to one JSONL line.

    Attributes:
        agent_id: Identity of the agent that was observed (matched to the graph
            agent node by name/scope on ingestion).
        kind: One of :class:`IncidentKind`.
        observed_at: ISO-8601 timestamp, injected by the caller (never derived
            here) so emission stays deterministic.
        severity: Incident severity (``critical``/``high``/``medium``/...).
        observed_node_ids: Graph node ids the agent was observed reaching
            (e.g. credential / privileged-tool node ids), when known.
        observed_tool_labels: Human-readable tool/resource labels reached, when
            a stable node id is not available.
        count: Number of underlying events this record aggregates (>=1).
        detail: Free-form, sanitized context (message, detector name, ...).
    """

    agent_id: str
    kind: str
    observed_at: str
    severity: str = "high"
    observed_node_ids: list[str] = field(default_factory=list)
    observed_tool_labels: list[str] = field(default_factory=list)
    count: int = 1
    detail: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "agent_id": sanitize_text(self.agent_id, max_len=300),
            "kind": sanitize_text(self.kind, max_len=64),
            "observed_at": sanitize_text(self.observed_at, max_len=64),
            "severity": sanitize_text(self.severity, max_len=32),
            "observed_node_ids": [sanitize_text(nid, max_len=300) for nid in self.observed_node_ids if str(nid).strip()],
            "observed_tool_labels": [sanitize_text(lbl, max_len=200) for lbl in self.observed_tool_labels if str(lbl).strip()],
            "count": max(1, int(self.count or 1)),
            "detail": {str(k): sanitize_text(v, max_len=400) for k, v in (self.detail or {}).items()},
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "RuntimeIncidentRecord | None":
        """Parse one JSONL record. Returns ``None`` for malformed/unknown rows.

        Tolerant by design: a corrupt or schema-mismatched line is skipped, not
        raised on, so a single bad row can never abort a scan's graph build.
        """
        if not isinstance(payload, Mapping):
            return None
        if str(payload.get("schema_version", "")) != SCHEMA_VERSION:
            return None
        agent_id = sanitize_text(payload.get("agent_id", ""), max_len=300)
        kind = sanitize_text(payload.get("kind", ""), max_len=64)
        if not agent_id or kind not in _KIND_ATTRIBUTE:
            return None
        raw_node_ids = payload.get("observed_node_ids")
        node_ids: list[Any] = raw_node_ids if isinstance(raw_node_ids, list) else []
        raw_labels = payload.get("observed_tool_labels")
        labels: list[Any] = raw_labels if isinstance(raw_labels, list) else []
        detail = payload.get("detail")
        raw_count = payload.get("count", 1)
        try:
            count = max(1, int(raw_count) if isinstance(raw_count, (int, str)) else 1)
        except (TypeError, ValueError):
            count = 1
        return cls(
            agent_id=agent_id,
            kind=kind,
            observed_at=sanitize_text(payload.get("observed_at", ""), max_len=64),
            severity=sanitize_text(payload.get("severity", "high"), max_len=32),
            observed_node_ids=[sanitize_text(n, max_len=300) for n in node_ids if isinstance(n, str) and n.strip()],
            observed_tool_labels=[sanitize_text(lbl, max_len=200) for lbl in labels if isinstance(lbl, str) and lbl.strip()],
            count=count,
            detail={str(k): sanitize_text(v, max_len=400) for k, v in detail.items()} if isinstance(detail, Mapping) else {},
        )


def resolve_sink_path(explicit: str | os.PathLike[str] | None = None) -> Path | None:
    """Resolve the feedback sink path: explicit arg wins, else env, else None.

    Returns ``None`` (feedback disabled) when neither is set — the default-off
    posture. An empty/whitespace value is treated as unset.
    """
    candidate = explicit if explicit is not None else os.environ.get(ENV_FEEDBACK_PATH)
    if candidate is None:
        return None
    text = str(candidate).strip()
    if not text:
        return None
    return Path(text)


class RuntimeIncidentSink:
    """Append-only JSONL sink for runtime incident records.

    Constructed with a resolved path (or ``None``). When the path is ``None``
    the sink is *inert*: :meth:`emit` is a no-op and :attr:`enabled` is False.
    All write failures are swallowed (logged at debug) so a runtime relay is
    never broken by feedback bookkeeping.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._path = resolve_sink_path(path)

    @property
    def enabled(self) -> bool:
        return self._path is not None

    @property
    def path(self) -> Path | None:
        return self._path

    def emit(self, record: RuntimeIncidentRecord) -> bool:
        """Append one record as a JSONL line. Returns True if written.

        Default-off: when no sink path is configured this returns False without
        touching disk. Never raises.
        """
        if self._path is None:
            return False
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record.to_dict(), separators=(",", ":"), sort_keys=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            return True
        except (OSError, TypeError, ValueError):
            logger.debug("Could not emit runtime incident feedback (non-fatal)", exc_info=True)
            return False


def load_incident_records(path: str | os.PathLike[str] | None) -> list[RuntimeIncidentRecord]:
    """Load and parse runtime incident records from a JSONL file.

    Fail-safe: a missing path, unreadable file, or malformed lines yield an
    empty list / skipped rows rather than an exception. Absent data ⇒ no records
    ⇒ the graph build behaves exactly as it does today.
    """
    resolved = resolve_sink_path(path)
    if resolved is None or not resolved.exists():
        return []
    records: list[RuntimeIncidentRecord] = []
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError:
        logger.debug("Could not read runtime incident feedback file (non-fatal)", exc_info=True)
        return []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        record = RuntimeIncidentRecord.from_dict(payload) if isinstance(payload, Mapping) else None
        if record is not None:
            records.append(record)
    return records


def incident_attribute(kind: str) -> str | None:
    """Return the ``observed_*`` agent-node attribute name for an incident kind."""
    return _KIND_ATTRIBUTE.get(kind)


def iter_observed_targets(record: RuntimeIncidentRecord) -> Iterator[tuple[str, bool]]:
    """Yield ``(target, is_node_id)`` for each observed reach in a record.

    Node ids (``is_node_id=True``) become edge endpoints directly; tool labels
    (``is_node_id=False``) are projected as synthetic observed-tool nodes by the
    builder. De-duplicated, order-stable.
    """
    seen: set[str] = set()
    for nid in record.observed_node_ids:
        key = f"id::{nid}"
        if nid and key not in seen:
            seen.add(key)
            yield nid, True
    for label in record.observed_tool_labels:
        key = f"label::{label}"
        if label and key not in seen:
            seen.add(key)
            yield label, False


def merge_records(records: Iterable[RuntimeIncidentRecord]) -> dict[str, list[RuntimeIncidentRecord]]:
    """Group incident records by ``agent_id`` for graph projection."""
    grouped: dict[str, list[RuntimeIncidentRecord]] = {}
    for record in records:
        grouped.setdefault(record.agent_id, []).append(record)
    return grouped
