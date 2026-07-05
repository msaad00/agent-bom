"""Tests for commit message hygiene guard."""

from __future__ import annotations

from scripts.check_commit_message import check_commit_message, strip_forbidden_trailers


def test_allows_clean_commit_message() -> None:
    assert check_commit_message("feat(cli): skip update check in offline mode\n") == []


def test_rejects_cursor_co_author_trailer() -> None:
    msg = "feat: example\n\nCo-authored-by: Cursor <cursoragent@cursor.com>\n"
    violations = check_commit_message(msg)
    assert violations
    assert any("co-author" in item.lower() for item in violations)


def test_rejects_made_with_cursor_trailer() -> None:
    msg = "docs: example\n\nMade with [Cursor](https://cursor.com)\n"
    violations = check_commit_message(msg)
    assert violations
    assert any("cursor" in item.lower() for item in violations)


def test_strip_removes_injected_trailers() -> None:
    msg = "feat: example\n\nCo-authored-by: Cursor <cursoragent@cursor.com>\n"
    assert strip_forbidden_trailers(msg) == "feat: example\n"
