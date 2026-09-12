"""Contracts for the fail-closed CI path classifier."""

from __future__ import annotations

from scripts.classify_ci_changes import classify_paths


def test_readme_and_documentation_changes_are_docs_only() -> None:
    result = classify_paths(
        [
            "README.md",
            "docs/operations/CI_RUNBOOK.md",
            "site-docs/getting-started.md",
            "mkdocs.yml",
        ]
    )

    assert result.docs_only is True
    assert result.changed_count == 4


def test_docs_only_allows_public_documentation_assets() -> None:
    result = classify_paths(
        [
            "docs/images/dashboard-light.png",
            "site-docs/assets/stylesheets/extra.css",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
        ]
    )

    assert result.docs_only is True


def test_mixed_documentation_and_product_change_fails_closed() -> None:
    result = classify_paths(["README.md", "src/agent_bom/api/server.py"])

    assert result.docs_only is False


def test_workflow_dependency_and_ui_changes_are_not_docs_only() -> None:
    for path in (
        ".github/workflows/ci.yml",
        "pyproject.toml",
        "uv.lock",
        "ui/app/page.tsx",
        "deploy/helm/agent-bom/values.yaml",
    ):
        assert classify_paths([path]).docs_only is False, path


def test_empty_or_malformed_path_input_fails_closed() -> None:
    assert classify_paths([]).docs_only is False
    assert classify_paths(["", "../README.md"]).docs_only is False


def test_source_edits_do_not_change_frozen_python_dependency_inputs() -> None:
    for path in ["README.md", "docs/images/graph.png", "ui/app/page.tsx"]:
        result = classify_paths([path])
        assert result.python_dependencies is False
    assert classify_paths(["src/agent_bom/output/sarif.py"]).python_dependencies is False


def test_dependency_routing_includes_lockfiles_packaging_and_install_tooling() -> None:
    for path in [
        "uv.lock",
        "pyproject.toml",
        "setup.py",
        "dashboard/requirements.txt",
        "requirements/test.in",
        "constraints-prod.txt",
        ".python-version",
        ".github/actions/setup-python/action.yml",
        ".github/workflows/pr-security-gate.yml",
        "scripts/classify_ci_changes.py",
    ]:
        result = classify_paths([path])
        assert result.python_dependencies is True, path


def test_security_routing_fails_closed_on_unknown_or_ambiguous_paths() -> None:
    for paths in [[], ["../README.md"], ["README.md", ""], ["new-surface/unknown.data"]]:
        result = classify_paths(paths)
        assert result.python_dependencies is True
