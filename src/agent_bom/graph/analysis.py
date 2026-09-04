"""Typed execution status for snapshot-wide graph analyses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from agent_bom.evidence.semantics import CompletenessEntry


class GraphAnalysisState(str, Enum):
    COMPLETE = "complete"
    LIMITED = "limited"
    SKIPPED = "skipped"
    FAILED = "failed"
    NOT_RECORDED = "not_recorded"


@dataclass(frozen=True, slots=True)
class GraphAnalysisStatus:
    """Secret-safe, serializable status for one graph analyzer."""

    status: GraphAnalysisState
    reason_codes: tuple[str, ...] = ()
    limits: Mapping[str, int] = field(default_factory=dict)
    observed: Mapping[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "limits": {str(key): int(value) for key, value in self.limits.items()},
            "observed": {str(key): int(value) for key, value in self.observed.items()},
        }

    def to_completeness_entry(self, *, component: str) -> CompletenessEntry:
        """Project this analyzer status without changing snapshot serialization."""

        from agent_bom.evidence.semantics import CompletenessEntry, EvidenceStage, EvidenceStatus

        status_map = {
            GraphAnalysisState.COMPLETE: EvidenceStatus.COMPLETE,
            GraphAnalysisState.LIMITED: EvidenceStatus.PARTIAL,
            GraphAnalysisState.SKIPPED: EvidenceStatus.UNAVAILABLE,
            GraphAnalysisState.FAILED: EvidenceStatus.FAILED,
            GraphAnalysisState.NOT_RECORDED: EvidenceStatus.UNAVAILABLE,
        }
        reasons = self.reason_codes
        if not reasons and self.status is not GraphAnalysisState.COMPLETE:
            reasons = (self.status.value,)
        return CompletenessEntry(
            stage=EvidenceStage.ANALYSIS,
            component=component,
            status=status_map[self.status],
            returned_count=max(self.observed.values(), default=None),
            reason_codes=reasons,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GraphAnalysisStatus:
        try:
            state = GraphAnalysisState(str(data.get("status", "not_recorded")))
        except ValueError:
            state = GraphAnalysisState.NOT_RECORDED
        return cls(
            status=state,
            reason_codes=tuple(str(code) for code in data.get("reason_codes", ()) if isinstance(code, str) and code),
            limits=_integer_mapping(data.get("limits")),
            observed=_integer_mapping(data.get("observed")),
        )


def _integer_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int] = {}
    for key, candidate in value.items():
        if isinstance(candidate, bool):
            continue
        try:
            result[str(key)] = int(candidate)
        except (TypeError, ValueError):
            continue
    return result


def analysis_status_map_to_dict(statuses: Mapping[str, GraphAnalysisStatus]) -> dict[str, dict[str, Any]]:
    return {str(name): status.to_dict() for name, status in sorted(statuses.items())}


def analysis_status_map_from_dict(value: Any) -> dict[str, GraphAnalysisStatus]:
    if not isinstance(value, Mapping):
        value = {}
    statuses = {str(name): GraphAnalysisStatus.from_dict(payload) for name, payload in value.items() if isinstance(payload, Mapping)}
    if "attack_path_fusion" not in statuses:
        statuses["attack_path_fusion"] = not_recorded_analysis_status()
    return statuses


def not_recorded_analysis_status() -> GraphAnalysisStatus:
    return GraphAnalysisStatus(
        status=GraphAnalysisState.NOT_RECORDED,
        reason_codes=("legacy_snapshot",),
    )
