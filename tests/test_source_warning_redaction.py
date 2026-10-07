"""Scanning source must not let Python print private paths or source literals."""

import warnings

import pytest

from agent_bom.ai_components.framework_agents import _scan_python_file
from agent_bom.ast.application_entrypoints import _python_entries
from agent_bom.parsers.skill_audit_behavior import _scan_python_ast_risks
from agent_bom.python_agents import _extract_agent_defs


@pytest.mark.parametrize("scanner", ["agents", "frameworks", "entrypoints", "skills"])
def test_source_syntax_warning_does_not_escape_scanner(scanner, tmp_path):
    source = 'token = "synthetic-secret\\q"\n'
    path = tmp_path / "private-agent.py"
    path.write_text(source)
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        if scanner == "agents":
            _extract_agent_defs(source, str(path))
        elif scanner == "frameworks":
            _scan_python_file(path, tmp_path)
        elif scanner == "entrypoints":
            _python_entries(tmp_path, path, source)
        else:
            _scan_python_ast_risks({"SKILL.md": f"```python\n{source}```"})
    assert not [item for item in observed if issubclass(item.category, SyntaxWarning)]


def test_concurrent_source_parses_do_not_restore_warning_output_mid_parse(monkeypatch):
    import ast
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from types import SimpleNamespace

    from agent_bom.ast import source_reader
    from agent_bom.ast.source_reader import parse_python_source

    first_entered, second_called, second_entered, first_done = (Event() for _ in range(4))

    def parser(source, **kwargs):
        if source == "first":
            first_entered.set()
            assert second_called.wait(3)
            # A serialized parser keeps the second call outside its warning
            # context until the first call returns; concurrent parsing enters.
            second_entered.wait(0.2)
        else:
            second_entered.set()
            assert first_done.wait(3)
            warnings.warn("synthetic private source", SyntaxWarning)
        return ast.Module(body=[], type_ignores=[])

    def first():
        try:
            return parse_python_source("first")
        finally:
            first_done.set()

    def second():
        assert first_entered.wait(3)
        second_called.set()
        return parse_python_source("second")

    monkeypatch.setattr(source_reader, "ast", SimpleNamespace(parse=parser))
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        with ThreadPoolExecutor(max_workers=2) as workers:
            a, b = workers.submit(first), workers.submit(second)
            a.result(timeout=5)
            b.result(timeout=5)
    assert not observed
