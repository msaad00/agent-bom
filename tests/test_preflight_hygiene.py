"""Release-preflight hygiene contracts."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_preflight_fix_only_regenerates_owned_artifacts() -> None:
    """Artifact regeneration must not rewrite unrelated source and tests."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("preflight-fix:", 1)[1].split("\n\n", 1)[0]

    assert "ruff format" not in target
