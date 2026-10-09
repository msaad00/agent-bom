"""The import-graph contract: domain stays below graph/api, no module-level cycle, SCC only shrinks."""

import ast
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from scripts import check_import_graph as graph

ROOT = Path(__file__).resolve().parents[1]


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, source in {"__init__.py": "", **files}.items():
        path = root / "src" / "agent_bom" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return root


def test_edges_are_classified_as_module_deferred_or_type():
    tree = ast.parse(
        "from typing import TYPE_CHECKING\n"
        "import agent_bom.a\n"
        "if TYPE_CHECKING:\n import agent_bom.b\n"
        "def f():\n import agent_bom.c\n"
        "try:\n import agent_bom.d\nexcept ImportError:\n pass\n"
    )
    kinds = {node.names[0].name: kind for node, kind in graph.import_nodes(tree.body) if isinstance(node, ast.Import)}
    assert kinds == {"agent_bom.a": "module", "agent_bom.b": "type", "agent_bom.c": "deferred", "agent_bom.d": "module"}


def test_relative_and_from_imports_resolve_to_the_named_submodule(tmp_path):
    root = _tree(tmp_path, {"pkg/__init__.py": "", "pkg/a.py": "from . import b\nfrom .b import thing\n", "pkg/b.py": "thing = 1\n"})
    edges = graph.build_graph(root)
    assert set(edges["agent_bom.pkg.a"]) == {"agent_bom.pkg.b"}


def test_deferred_cycle_counts_toward_scc_but_not_module_level_cycles(tmp_path):
    root = _tree(tmp_path, {"a.py": "import agent_bom.b\n", "b.py": "def f():\n    import agent_bom.a\n"})
    result = graph.measure(root)
    assert result["max_scc"] == 2
    assert result["top_level_cycles"] == []


def test_annotation_only_cycle_is_a_module_level_cycle_but_not_runtime_coupling(tmp_path):
    root = _tree(
        tmp_path,
        {"a.py": "import agent_bom.b\n", "b.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import agent_bom.a\n"},
    )
    result = graph.measure(root)
    assert result["max_scc"] == 1
    assert result["top_level_cycles"] == [["agent_bom.a", "agent_bom.b"]]


@pytest.mark.parametrize(
    "source",
    [
        "from agent_bom.graph.sla import finding_owner\n",
        "def f():\n    from agent_bom.api import server\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from agent_bom.cloud import aws\n",
        "def f():\n    from agent_bom.exploitability import fused_triage_priority\n",
    ],
)
def test_domain_module_cannot_import_upward_with_any_edge_kind(tmp_path, source):
    files = {"models.py": source, "graph/__init__.py": "", "graph/sla.py": "", "api/__init__.py": "", "api/server.py": ""}
    files |= {"cloud/__init__.py": "", "cloud/aws.py": "", "exploitability.py": ""}
    errors = graph.measure(_tree(tmp_path, files))["domain_errors"]
    assert len(errors) == 1 and errors[0].startswith("src/agent_bom/models.py:")


def test_domain_module_may_import_core_and_peers(tmp_path):
    files = {"models.py": "from agent_bom.core import sla\nfrom agent_bom import finding\n", "core/__init__.py": "", "core/sla.py": ""}
    assert graph.measure(_tree(tmp_path, {**files, "finding.py": ""}))["domain_errors"] == []


def test_scc_growth_over_baseline_fails_and_shrink_can_be_recorded(tmp_path):
    root = _tree(tmp_path, {"a.py": "import agent_bom.b\n", "b.py": "def f():\n    import agent_bom.a\n"})
    baseline = root / graph.BASELINE
    baseline.parent.mkdir(parents=True)
    baseline.write_text(json.dumps({"max_scc": 1}))
    errors, _ = graph.check(root)
    assert any("exceeds baseline 1" in error for error in errors)
    errors, _ = graph.check(root, write_baseline=True)
    assert errors and json.loads(baseline.read_text())["max_scc"] == 1, "growth is never written"
    baseline.write_text(json.dumps({"max_scc": 5}))
    errors, _ = graph.check(root, write_baseline=True)
    assert not errors and json.loads(baseline.read_text())["max_scc"] == 2


def test_baseline_cannot_be_raised_above_the_base_ref(tmp_path, monkeypatch):
    root = _tree(tmp_path, {"a.py": ""})
    (root / graph.BASELINE).parent.mkdir(parents=True)
    (root / graph.BASELINE).write_text(json.dumps({"max_scc": 9}))
    monkeypatch.setattr(graph, "base_ref_max_scc", lambda _root, _ref: 4)
    errors, _ = graph.check(root, base_ref="base")
    assert errors == [f"{graph.BASELINE}: max_scc 9 exceeds the base ref value 4"]


def test_repository_meets_the_import_contract():
    result = graph.measure(ROOT)
    recorded = json.loads((ROOT / graph.BASELINE).read_text())["max_scc"]
    assert result["domain_errors"] == []
    assert result["top_level_cycles"] == []
    assert result["max_scc"] <= recorded


def test_loading_domain_models_does_not_load_graph_api_or_cloud_layers():
    probe = textwrap.dedent(
        """
        import sys
        from agent_bom.finding import Asset, Finding, FindingSource, FindingType
        from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability

        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vuln = Vulnerability(id="CVE-1", summary="s", severity=Severity.HIGH, cvss_vector=vector)
        pkg = Package(name="p", version="1", ecosystem="pypi", vulnerabilities=[vuln])
        br = BlastRadius(
            vulnerability=vuln, package=pkg, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[]
        )
        br.calculate_risk_score()
        assert br.reachability in {"confirmed", "likely", "unlikely", "unknown"}
        asset = Asset(name="p", asset_type="mcp_server")
        finding = Finding(finding_type=FindingType.CVE, source=FindingSource.MCP_SCAN, asset=asset, severity="high", title="t")
        assert finding.entity_type == "server" and "sla_due_at" in finding.to_dict()
        report = AIBOMReport(agents=[], blast_radii=[br], toxic_combination_findings_data=[{"title": "x", "id": "f1"}])
        assert len(report.to_findings()) == 2
        assert vuln.network_exploitable
        upper = (["agent_bom", "graph"], ["agent_bom", "api"], ["agent_bom", "cloud"])
        print(sorted(m for m in sys.modules if m.split(".")[:2] in upper))
        """
    )
    run = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True, cwd=ROOT)
    assert run.stdout.strip() == "[]"
