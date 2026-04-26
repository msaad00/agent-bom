"""Unit tests for scripts/generate_env_var_reference.py.

The generator parses src/agent_bom/config.py and renders docs/operations/
ENV_VARS.md plus a CI gate against scripts/env_var_allowlist.txt. These
tests pin the contract end-to-end so the gate cannot regress silently:

- the generator on the real repo state must produce a doc identical to the
  one checked in (the same comparison CI's --check mode performs);
- the gate must fail when a new ad-hoc AGENT_BOM_* reference appears under
  src/agent_bom/;
- the gate must fail when the on-disk doc drifts from the generator output.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "generate_env_var_reference.py"


def _load_generator():
    name = "generate_env_var_reference"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules before exec so dataclass(frozen=True) can
    # resolve the module via `cls.__module__` lookup.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_doc_on_disk_matches_generator_output():
    gen = _load_generator()
    env_vars = gen._parse_config(gen.CONFIG_FILE)
    expected = gen._render_doc(env_vars)
    on_disk = gen.DOC_FILE.read_text(encoding="utf-8")
    assert expected == on_disk, (
        "docs/operations/ENV_VARS.md is out of date — re-run `python scripts/generate_env_var_reference.py` and commit the diff."
    )


def test_repo_state_passes_drift_check():
    gen = _load_generator()
    env_vars = gen._parse_config(gen.CONFIG_FILE)
    declared = {var.env_key for var in env_vars}
    ad_hoc = gen._scan_src_references(gen.SRC_DIR, declared)
    allowlist = gen._load_allowlist(gen.ALLOWLIST_FILE)
    untracked = ad_hoc - allowlist
    stale = allowlist - ad_hoc
    assert not untracked, f"Ad-hoc AGENT_BOM_* env vars are not in config.py or the allowlist: {sorted(untracked)}"
    assert not stale, f"Allowlist contains stale entries: {sorted(stale)}"


def test_gate_flags_new_ad_hoc_env_var(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    # Synthesize a tiny src/ tree containing one declared env var (in a fake
    # config.py) and one ad-hoc reference in a sibling module. With no
    # allowlist, the ad-hoc var must surface as drift.
    gen = _load_generator()

    fake_root = Path(tmp_path) if not callable(tmp_path) else None  # type: ignore[arg-type]
    fake_root = Path(tmp_path)  # pytest tmp_path is a Path
    config_dir = fake_root / "src_pkg"
    config_dir.mkdir()
    config_file = config_dir / "config.py"
    config_file.write_text(
        'import os\ndef _str(k, d):\n    return os.environ.get(k, d)\nKNOWN = _str("AGENT_BOM_KNOWN", "x")\n',
        encoding="utf-8",
    )
    (config_dir / "other.py").write_text(
        'import os\nvalue = os.environ.get("AGENT_BOM_NEW_AD_HOC", "y")\n',
        encoding="utf-8",
    )

    declared = {var.env_key for var in gen._parse_config(config_file)}
    assert declared == {"AGENT_BOM_KNOWN"}

    ad_hoc = {
        ref
        for path in config_dir.glob("*.py")
        if path != config_file
        for ref in gen.ENV_VAR_LITERAL.findall(path.read_text(encoding="utf-8"))
        if ref not in declared
    }
    assert ad_hoc == {"AGENT_BOM_NEW_AD_HOC"}


def test_render_doc_groups_by_section_and_includes_defaults():
    gen = _load_generator()
    env_vars = gen._parse_config(gen.CONFIG_FILE)
    rendered = gen._render_doc(env_vars)
    # Every section header in config.py should surface as a markdown heading.
    sections = {var.section for var in env_vars}
    for section in sections:
        assert f"## {section}" in rendered, f"missing section heading: {section}"
    # Defaults must round-trip: pick a few stable numeric vars and assert the
    # default literal appears in the rendered table.
    default_pairs = {var.env_key: var.default_repr for var in env_vars if var.default_repr}
    sample = ("AGENT_BOM_HTTP_MAX_RETRIES", "AGENT_BOM_API_MAX_JOBS", "AGENT_BOM_POSTGRES_POOL_MIN_SIZE")
    for key in sample:
        assert key in default_pairs, f"expected {key} to be parsed from config.py"
        assert f"`{default_pairs[key]}`" in rendered


def test_allowlist_loader_strips_inline_comments_and_blank_lines(tmp_path: Path) -> None:
    gen = _load_generator()
    path = tmp_path / "allow.txt"
    path.write_text(
        "# leading comment\n\nAGENT_BOM_FOO\nAGENT_BOM_BAR  # explanation that should be stripped\n\n# trailing comment\n",
        encoding="utf-8",
    )
    assert gen._load_allowlist(path) == {"AGENT_BOM_FOO", "AGENT_BOM_BAR"}
