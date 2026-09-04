"""Graph-analysis execution states project to canonical completeness."""

from agent_bom.evidence.semantics import EvidenceStage, EvidenceStatus
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus


def test_graph_analysis_state_adapter_preserves_incomplete_truth() -> None:
    expected = {
        GraphAnalysisState.COMPLETE: EvidenceStatus.COMPLETE,
        GraphAnalysisState.LIMITED: EvidenceStatus.PARTIAL,
        GraphAnalysisState.SKIPPED: EvidenceStatus.UNAVAILABLE,
        GraphAnalysisState.FAILED: EvidenceStatus.FAILED,
        GraphAnalysisState.NOT_RECORDED: EvidenceStatus.UNAVAILABLE,
    }

    for state, status in expected.items():
        entry = GraphAnalysisStatus(status=state, reason_codes=(state.value,)).to_completeness_entry(component="attack-path-fusion")
        assert entry.stage is EvidenceStage.ANALYSIS
        assert entry.status is status
        assert entry.reason_codes == (state.value,)


def test_limited_analysis_can_never_project_complete() -> None:
    entry = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED,
        reason_codes=("node_cap_exceeded",),
        limits={"max_nodes": 1000},
        observed={"node_count": 1500},
    ).to_completeness_entry(component="attack-path-fusion")

    assert entry.status is EvidenceStatus.PARTIAL
    assert entry.returned_count == 1500
    assert entry.expected_count is None
