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
