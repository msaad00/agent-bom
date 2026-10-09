"""One source walk per scan, without dropping consumed coverage evidence."""

from pathlib import Path

from agent_bom.ast.project_scope import analyze_project_once, project_analysis_scope
from agent_bom.scanners.state import consume_coverage_warnings, record_coverage_warning


def test_reuses_analysis_and_replays_consumed_warnings(monkeypatch, tmp_path):
    calls = []
    warning = {"release": "ast-analysis:project-file-budget", "reason": "partial"}

    def analyze(path):
        calls.append(path)
        record_coverage_warning(warning)
        return object()

    monkeypatch.setattr("agent_bom.ast_analyzer.analyze_project", analyze)
    consume_coverage_warnings()
    with project_analysis_scope():
        first = analyze_project_once(tmp_path)
        assert consume_coverage_warnings() == [warning]
        assert analyze_project_once(str(tmp_path)) is first
        assert consume_coverage_warnings() == [warning]
        assert len(calls) == 1
    with project_analysis_scope():
        assert analyze_project_once(tmp_path) is not first
    assert len(calls) == 2
    consume_coverage_warnings()


def test_cli_discovery_and_late_stage_share_one_scan_scope(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from agent_bom.ast_analyzer import ASTAnalysisResult
    from agent_bom.cli.agents.scan_pipeline.late import _analyze_source
    from agent_bom.cli.agents.scan_pipeline.runner import run_scan
    from agent_bom.python_agents import _prompt_inventory_by_file

    calls = []

    def analyze(path):
        calls.append(path)
        return ASTAnalysisResult()

    monkeypatch.setattr("agent_bom.ast_analyzer.analyze_project", analyze)
    monkeypatch.setattr("agent_bom.ast_analyzer.project_has_analyzable_sources", lambda _: True)
    opts = SimpleNamespace(project=str(tmp_path), skill_only=False, dry_run=False)
    run_scan(opts, stages=(("discovery", lambda o, s: _prompt_inventory_by_file(Path(o.project))), ("late", _analyze_source)))
    assert len(calls) == 1
    run_scan(opts, stages=(("discovery", lambda o, s: _prompt_inventory_by_file(Path(o.project))),))
    assert len(calls) == 2
