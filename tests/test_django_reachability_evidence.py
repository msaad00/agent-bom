"""Django route evidence and absent analysis must not imply safety."""

from agent_bom.ast_analyzer import analyze_project
from agent_bom.reachability_cve import SymbolReachIndex, classify_reachability


def test_django_imported_function_view_is_an_entrypoint(tmp_path):
    (tmp_path / "views.py").write_text("import yaml\ndef decode(request):\n    return yaml.load(request.body)\n")
    (tmp_path / "urls.py").write_text(
        'from django.urls import path as route\nfrom views import decode\nurlpatterns = [route("decode/", decode)]\n'
    )
    result = analyze_project(tmp_path)
    assert any(e.handler == "decode" and e.file_path == "views.py" and e.framework == "Django" for e in result.application_entrypoints)
    assert SymbolReachIndex.from_ast_result(result).is_package_reached("PyYAML", ecosystem="pypi")


def test_missing_application_roots_leave_reachability_unknown(tmp_path):
    (tmp_path / "views.py").write_text("import yaml\ndef dynamically_registered(request):\n    return yaml.load(request.body)\n")
    result = analyze_project(tmp_path)
    signal = classify_reachability(package="PyYAML", advisory=None, index=SymbolReachIndex.from_ast_result(result))
    assert signal.state == "unknown"


def test_non_django_path_function_is_not_route_evidence(tmp_path):
    (tmp_path / "urls.py").write_text(
        'def path(route, fn): return fn\ndef decode(request): return None\nurlpatterns = [path("decode/", decode)]\n'
    )
    assert not analyze_project(tmp_path).application_entrypoints


def test_unknown_analysis_is_not_upgraded_by_dependency_association():
    from agent_bom.graph.reachability_truth import assess_reachability

    assert assess_reachability(symbol_reachability="unknown", direct_dependency=True, affected_agents=True).verdict.value == "unknown"


def test_imported_django_handler_does_not_emit_source_syntax_warnings(tmp_path):
    import ast
    import warnings

    from agent_bom.ast.django_entrypoints import django_entries

    urls = tmp_path / "urls.py"
    urls.write_text('from django.urls import path\nfrom views import handler\nurlpatterns = [path("", handler)]\n')
    (tmp_path / "views.py").write_text('def handler(request):\n    return "private-value\\q"\n')
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always", SyntaxWarning)
        assert django_entries(tmp_path, urls, ast.parse(urls.read_text()))
    assert not emitted
