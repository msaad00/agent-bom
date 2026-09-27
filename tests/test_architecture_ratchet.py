"""Architecture debt cannot grow or move into a newly oversized function."""

import ast

from scripts.check_architecture import baseline_growth, boundary_errors, debt, function_spans, measure, regressions


def test_new_and_growing_debt_fails_but_reductions_pass():
    baseline = {"old.py::big": {"function_lines": 100}}
    assert regressions({"old.py::big": {"function_lines": 101}}, baseline)
    assert regressions({"new.py::big": {"function_lines": 81}}, baseline)
    assert not regressions({"old.py::big": {"function_lines": 90}}, baseline)
    reduced = debt({"old.py::big": {"function_lines": 90}})
    assert regressions({"old.py::big": {"function_lines": 91}}, reduced)


def test_nested_functions_have_distinct_qualified_names():
    tree = ast.parse("class One:\n def work(self):\n  def inner():\n   pass\nclass Two:\n def work(self):\n  pass\n")
    assert [name for name, _, _ in function_spans(tree)] == ["One.work", "One.work.inner", "Two.work"]


def test_kernel_rejects_absolute_relative_and_deferred_adapter_imports():
    for source in ("from agent_bom.api import server", "from ..api import server", "def f():\n import agent_bom.models"):
        assert boundary_errors("core/example.py", ast.parse(source))
    assert not boundary_errors("core/example.py", ast.parse("from .severity import Severity\nimport math"))


def test_semantic_owner_cannot_be_reimplemented_in_adapter():
    tree = ast.parse("def normalize_severity(value):\n return value\n")
    assert boundary_errors("api/example.py", tree)
    assert not boundary_errors("core/severity.py", tree)


def test_editing_baseline_cannot_approve_new_or_larger_exceptions():
    previous = {"old.py": {"file_lines": 700}}
    assert baseline_growth({"old.py": {"file_lines": 701}}, previous)
    assert baseline_growth({"new.py": {"file_lines": 650}}, previous)
    assert not baseline_growth({"old.py": {"file_lines": 690}}, previous)


def test_complexity_cannot_be_hidden_with_noqa(tmp_path):
    root = tmp_path / "src" / "agent_bom"
    root.mkdir(parents=True)
    body = "def hidden(value):  # noqa: C901\n" + "".join(f"    if value == {i}:\n        return {i}\n" for i in range(16))
    (root / "sample.py").write_text(body)
    metrics, errors = measure(tmp_path)
    assert not errors
    assert metrics["sample.py::hidden"]["complexity"] == 17
    assert regressions(metrics, {})
