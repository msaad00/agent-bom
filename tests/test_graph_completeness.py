from agent_bom.graph.completeness import graph_completeness


def test_graph_completeness_defaults_to_complete():
    assert graph_completeness(returned=3, total=3) == {
        "status": "complete",
        "complete": True,
        "sampled": False,
        "truncated": False,
        "returned": 3,
        "total": 3,
    }


def test_graph_completeness_distinguishes_sampled_and_truncated():
    sampled = graph_completeness(returned=10, sampled=True, reason="source budget")
    truncated = graph_completeness(returned=10, total=100, truncated=True, reason="page limit")
    assert sampled["status"] == "sampled"
    assert sampled["complete"] is False
    assert truncated["status"] == "truncated"
    assert truncated["total"] == 100
