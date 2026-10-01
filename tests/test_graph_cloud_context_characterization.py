"""Cloud context extraction preserves complete graph evidence and ordering."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.graph.builder import build_unified_graph_from_report

FIXTURES = Path(__file__).parent / "fixtures" / "graph_cloud_context"


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 9, 30, 12, tzinfo=timezone.utc)


def test_cloud_context_graph_characterization(monkeypatch):
    # Freeze only the builder clock. Source observation timestamps remain data.
    monkeypatch.setattr("agent_bom.graph.util.datetime", FrozenDatetime)
    reports = json.loads((FIXTURES / "reports.json").read_text())
    actual = {}
    for name, report in reports.items():
        graph = build_unified_graph_from_report(report, scan_id="cloud-context", tenant_id="tenant-a")
        assert graph.nodes and graph.edges, name
        actual[name] = graph.to_dict()
    golden = FIXTURES / "graphs.json"
    if os.environ.get("AGENT_BOM_UPDATE_GOLDENS") == "1":
        golden.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    assert actual == json.loads(golden.read_text())
