"""Repository ignore semantics for project secret scanning.

The scanner must not report a "secret" that lives in a path the repository
already declares uninteresting. Before this suite the only exclusion was a
hardcoded directory-name allowlist (``traversal.VENDOR_SKIP_DIRS``), so any
ignored tool-artifact directory whose *name* happened to be absent from that
list was scanned in full — a real repository produced 213 CRITICAL findings
from a single gitignored browser-automation cache.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.secret_scanner import scan_secrets

# A pattern-matched credential, not entropy — so these tests exercise ignore
# semantics rather than the opt-in entropy detector.
_SECRET = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'


def _scanned_files(root: Path) -> set[str]:
    return {str(f.file_path).replace("\\", "/") for f in scan_secrets(str(root)).findings}


def test_gitignored_directory_is_not_scanned(tmp_path: Path) -> None:
    """A gitignored artifact directory is skipped even though its name is not
    in any hardcoded vendor list."""
    (tmp_path / ".gitignore").write_text(".playwright-mcp/\n")
    artifacts = tmp_path / ".playwright-mcp"
    artifacts.mkdir()
    (artifacts / "trace.js").write_text(_SECRET)

    assert not any(".playwright-mcp" in p for p in _scanned_files(tmp_path))


def test_source_outside_ignores_still_reports_its_secret(tmp_path: Path) -> None:
    """Guard against over-pruning: ignoring one path must not silence the rest."""
    (tmp_path / ".gitignore").write_text(".playwright-mcp/\n")
    (tmp_path / "app.py").write_text(_SECRET)

    assert "app.py" in _scanned_files(tmp_path)


def test_negated_pattern_is_rescanned(tmp_path: Path) -> None:
    """``!keep.env`` re-includes a file an earlier pattern excluded."""
    (tmp_path / ".gitignore").write_text("*.env\n!keep.env\n")
    (tmp_path / "drop.env").write_text(_SECRET)
    (tmp_path / "keep.env").write_text(_SECRET)

    scanned = _scanned_files(tmp_path)
    assert "keep.env" in scanned
    assert "drop.env" not in scanned


def test_nested_gitignore_applies_to_its_own_subtree(tmp_path: Path) -> None:
    """A nested .gitignore governs its directory; a sibling stays scanned."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / ".gitignore").write_text("generated.py\n")
    (pkg / "generated.py").write_text(_SECRET)
    (pkg / "real.py").write_text(_SECRET)
    other = tmp_path / "other"
    other.mkdir()
    (other / "generated.py").write_text(_SECRET)

    scanned = _scanned_files(tmp_path)
    assert "pkg/generated.py" not in scanned
    assert "pkg/real.py" in scanned
    # The nested rule must not leak upward into a sibling subtree.
    assert "other/generated.py" in scanned


def test_anchored_pattern_matches_only_at_root(tmp_path: Path) -> None:
    """A leading-slash rule is anchored to the repository root."""
    (tmp_path / ".gitignore").write_text("/config.py\n")
    (tmp_path / "config.py").write_text(_SECRET)
    nested = tmp_path / "app"
    nested.mkdir()
    (nested / "config.py").write_text(_SECRET)

    scanned = _scanned_files(tmp_path)
    assert "config.py" not in scanned
    assert "app/config.py" in scanned


def test_agentbomignore_is_honored(tmp_path: Path) -> None:
    """The scanner-specific ignore file uses the same path-pattern semantics."""
    (tmp_path / ".agentbomignore").write_text("vendor-dump/\n")
    dump = tmp_path / "vendor-dump"
    dump.mkdir()
    (dump / "creds.py").write_text(_SECRET)
    (tmp_path / "app.py").write_text(_SECRET)

    scanned = _scanned_files(tmp_path)
    assert not any("vendor-dump" in p for p in scanned)
    assert "app.py" in scanned


def test_agentbomignore_can_reinclude_a_gitignored_path(tmp_path: Path) -> None:
    """Explicit precedence: .agentbomignore is evaluated after .gitignore, so a
    negation there re-includes a path git ignores."""
    (tmp_path / ".gitignore").write_text("secrets-fixture/\n")
    (tmp_path / ".agentbomignore").write_text("!secrets-fixture/\n!secrets-fixture/**\n")
    fixture = tmp_path / "secrets-fixture"
    fixture.mkdir()
    (fixture / "creds.py").write_text(_SECRET)

    assert any("secrets-fixture" in p for p in _scanned_files(tmp_path))


def test_explicitly_scanned_root_is_never_self_ignored(tmp_path: Path) -> None:
    """Preserved behavior: a root the caller passed is always walked."""
    (tmp_path / ".gitignore").write_text("*\n")
    (tmp_path / "app.py").write_text(_SECRET)

    result = scan_secrets(str(tmp_path))
    # Everything is ignored, so there are no findings — but a fully-ignored tree
    # must never read as a clean one: the coverage has to be disclosed.
    assert result.findings == []
    assert result.files_scanned == 0
    assert result.ignored_paths > 0
    assert any("ignore" in w.lower() for w in result.warnings), result.warnings


def test_ignored_coverage_is_disclosed(tmp_path: Path) -> None:
    """Skipping paths is a coverage claim; it must be represented honestly."""
    (tmp_path / ".gitignore").write_text(".playwright-mcp/\n")
    artifacts = tmp_path / ".playwright-mcp"
    artifacts.mkdir()
    (artifacts / "trace.js").write_text(_SECRET)
    (tmp_path / "app.py").write_text(_SECRET)

    result = scan_secrets(str(tmp_path))
    assert result.ignored_paths > 0, "ignored paths must be counted, not silently dropped"
