"""Structural version-alignment gate regression tests.

The gate scans whole shipping-surface trees (not a hand-maintained per-file
allowlist) for managed version/image references, so a NEW file that introduces a
pinned image or GitHub Action ref is covered automatically and cannot silently
drift away from the canonical pyproject version.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    mod_name = name.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def test_repo_is_aligned_to_canonical_version() -> None:
    """Every managed reference in the shipping surfaces equals pyproject version."""
    cva = _load_script("check_version_alignment.py")
    version = cva.canonical_version()
    drift = cva.find_drift(version)
    assert drift == [], "version drift detected:\n" + "\n".join(drift)


def test_scan_text_flags_stale_image_pin() -> None:
    cva = _load_script("check_version_alignment.py")
    text = "    image: agentbom/agent-bom-ui:0.97.0\n"
    drift = cva.scan_text("deploy/example.yml", text, "0.97.1")
    assert len(drift) == 1
    assert "deploy/example.yml:1" in drift[0]
    assert "0.97.0" in drift[0]
    assert "0.97.1" in drift[0]


def test_scan_text_flags_stale_action_ref() -> None:
    cva = _load_script("check_version_alignment.py")
    text = "- uses: msaad00/agent-bom@v0.90.0 # example\n"
    drift = cva.scan_text("docs/example.md", text, "0.97.1")
    assert len(drift) == 1
    assert "GitHub Action ref" in drift[0]


def test_scan_text_passes_when_aligned() -> None:
    cva = _load_script("check_version_alignment.py")
    text = "image: agentbom/agent-bom:0.97.1\nuses: msaad00/agent-bom@v0.97.1\n"
    assert cva.scan_text("deploy/example.yml", text, "0.97.1") == []


def test_latest_demo_image_must_not_be_pinned(tmp_path, monkeypatch) -> None:
    """A demo compose designated :latest can't silently freeze on an old pin."""
    cva = _load_script("check_version_alignment.py")
    demo = tmp_path / "docker-compose.demo.yml"
    demo.write_text("services:\n  api:\n    image: agent-bom:0.97.1\n")
    monkeypatch.setattr(cva, "SCAN_ROOTS", ())
    monkeypatch.setattr(cva, "LATEST_REQUIRED", (("docker-compose.demo.yml", "agent-bom:latest"),))
    monkeypatch.setattr(cva, "ROOT", tmp_path)
    drift = cva.find_drift("0.97.1")
    assert any("latest" in line for line in drift), drift

    demo.write_text("services:\n  api:\n    image: agent-bom:latest\n")
    assert cva.find_drift("0.97.1") == []


def test_rewrite_aligns_stale_refs(tmp_path, monkeypatch) -> None:
    cva = _load_script("check_version_alignment.py")
    stale = tmp_path / "guide.md"
    stale.write_text("run: uses: msaad00/agent-bom@v0.90.0\nimage: agentbom/agent-bom:0.90.0\n")
    monkeypatch.setattr(cva, "SCAN_ROOTS", (stale,))
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "ROOT", tmp_path)
    count, changed = cva.rewrite("0.97.1")
    assert count == 2
    assert changed == [stale]
    assert "0.90.0" not in stale.read_text()
    assert cva.find_drift("0.97.1") == []


# ---------------------------------------------------------------------------
# sdks/ version policy — writer/checker pairing
#
# `sdks/python` sat at 0.92.0 while the platform shipped 0.100.0 because nothing
# declared whether an SDK tracks the platform release or runs its own semver
# line. The classification and the structural sweep now live in ONE place,
# `scripts/check_release_consistency.py` (`INDEPENDENTLY_VERSIONED`), so this
# file does not keep a second copy of that judgement to disagree with.
#
# What is left here is the half a checker cannot assert about itself: every
# manifest the sweep expects to equal the release version must also be REWRITTEN
# by `bump-version.py`. A checker without a matching writer does not remove the
# manual step, it relocates it — which is how this drifted in the first place.
# ---------------------------------------------------------------------------


def _platform_tracking_sdk_manifests() -> list[str]:
    """SDK manifests the release sweep requires to equal the platform version."""
    consistency = _load_script("check_release_consistency.py")
    independent = set(consistency.INDEPENDENTLY_VERSIONED)
    found: list[str] = []
    for path in sorted((ROOT / "sdks").rglob("*")):
        if path.name not in {"pyproject.toml", "package.json"} or "node_modules" in path.parts:
            continue
        relative = str(path.relative_to(ROOT))
        if relative not in independent:
            found.append(relative)
    return found


def test_platform_tracking_sdks_are_owned_by_the_release_bump() -> None:
    tracking = _platform_tracking_sdk_manifests()
    assert tracking, "no platform-tracking SDK manifest found — the discovery below is broken"

    bump = _load_script("bump-version.py")
    managed = {rel for rel, _pattern, _template in bump.VERSION_LOCATIONS}
    missing = sorted(set(tracking) - managed)
    assert missing == [], f"SDK(s) checked by check_release_consistency but never written by bump-version.py: {missing}"


def test_each_sdk_manifest_is_registered_exactly_once_for_the_bump() -> None:
    """One registration per artifact — two that happen to agree still disagree later."""
    bump = _load_script("bump-version.py")
    sdk_entries = [rel for rel, _pattern, _template in bump.VERSION_LOCATIONS if rel.startswith("sdks/")]
    duplicates = sorted({rel for rel in sdk_entries if sdk_entries.count(rel) > 1})
    assert duplicates == [], f"bump-version.py registers the same SDK manifest more than once: {duplicates}"


def test_main_exits_nonzero_on_drift(tmp_path, monkeypatch, capsys) -> None:
    cva = _load_script("check_version_alignment.py")
    stale = tmp_path / "deploy.yml"
    stale.write_text("image: agentbom/agent-bom:0.90.0\n")
    monkeypatch.setattr(cva, "SCAN_ROOTS", (stale,))
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "ROOT", tmp_path)
    monkeypatch.setattr(cva, "canonical_version", lambda: "0.97.1")
    assert cva.main([]) == 1
    out = capsys.readouterr().out
    assert "0.90.0" in out
