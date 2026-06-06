"""Opt-in entropy detection catches novel secrets the named patterns miss."""

from __future__ import annotations

from pathlib import Path

from agent_bom.secret_scanner import _shannon_entropy, scan_secrets


def _novel_secret_value() -> str:
    return "".join(("aB3xK9mZ", "2pQ7rT5w", "Y8nL4vC1", "dF6gH0jM"))


def test_shannon_entropy_ranks_random_above_words():
    assert _shannon_entropy("aB3xK9mZ2pQ7rT5wY8nL4vC1") > 4.0
    assert _shannon_entropy("passwordpassword") < 3.0
    assert _shannon_entropy("") == 0.0


def _write(tmp_path: Path) -> Path:
    # A high-entropy value assigned to a secret-named key that no vendor
    # credential pattern names — only entropy detection can catch it.
    novel_secret = _novel_secret_value()
    (tmp_path / "config.py").write_text(
        f'INTERNAL_AUTH_VALUE = "{novel_secret}"\nPLACEHOLDER_TOKEN = "your-token-goes-here"\nTIMEOUT_SECONDS = 30\n'
    )
    return tmp_path


def test_entropy_off_by_default(tmp_path: Path):
    _write(tmp_path)
    result = scan_secrets(_write(tmp_path))
    assert not any(f.category == "entropy" for f in result.findings)


def test_entropy_on_flags_novel_secret(tmp_path: Path):
    _write(tmp_path)
    result = scan_secrets(tmp_path, detect_entropy=True)
    entropy = [f for f in result.findings if f.category == "entropy"]
    assert entropy, "high-entropy secret should be flagged when enabled"
    assert entropy[0].secret_type == "High-entropy secret"
    assert entropy[0].severity == "high"
    # the value itself is never echoed
    assert all("aB3xK9" not in f.matched_preview for f in result.findings)


def test_entropy_skips_placeholders_and_low_entropy(tmp_path: Path):
    _write(tmp_path)
    result = scan_secrets(tmp_path, detect_entropy=True)
    # the placeholder token and the numeric timeout must not be flagged
    assert all("your-token" not in f.matched_preview for f in result.findings)
    assert not any(f.line_number == 3 for f in result.findings if f.category == "entropy")
