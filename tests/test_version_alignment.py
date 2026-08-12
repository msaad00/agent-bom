"""Structural version-alignment gate regression tests.

The gate scans whole shipping-surface trees (not a hand-maintained per-file
allowlist) for managed version/image references, so a NEW file that introduces a
pinned image or GitHub Action ref is covered automatically and cannot silently
drift away from the canonical pyproject version.
"""

from __future__ import annotations

import importlib.util
import json
import re
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
# sdks/ version policy
#
# `sdks/python` sat at 0.92.0 while the platform shipped 0.100.0 because
# nothing declared whether an SDK tracks the platform release or runs its own
# semver line — so neither answer could be enforced and the drift was silent.
# Each manifest is now classified, and an SDK added later that is classified as
# neither fails this gate instead of quietly rotting.
# ---------------------------------------------------------------------------

SDK_TRACKS_PLATFORM: dict[str, str] = {
    "sdks/python/pyproject.toml": (
        "agent-bom-sdk adds no behaviour of its own: it re-exports "
        "agent_bom.client.AgentBomClient out of the `agent-bom` wheel it depends on. "
        "Its version therefore names the platform release it wraps, exactly as "
        "ui/package.json and the Helm chart do."
    ),
}

SDK_INDEPENDENT: dict[str, str] = {
    "sdks/typescript/package.json": (
        "@agent-bom/runtime is a standalone npm detector library with its own "
        "implementation and its own npm consumers — not a build of the platform. "
        "It keeps its own semver line."
    ),
    "sdks/typescript-client/package.json": (
        "@agent-bom/client is published on its own npm semver line; retagging it to "
        "the platform version would fabricate ~99 releases for npm consumers. It "
        "keeps its own semver line."
    ),
}


def _sdk_manifests() -> list[str]:
    """Every version-declaring manifest under sdks/ (go modules version by tag)."""
    found: list[str] = []
    for path in sorted((ROOT / "sdks").rglob("*")):
        if path.name not in {"pyproject.toml", "package.json"}:
            continue
        if "node_modules" in path.parts:
            continue
        if _manifest_version(path) is not None:
            found.append(str(path.relative_to(ROOT)))
    return found


def _manifest_version(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8")
    if path.name == "package.json":
        return json.loads(text).get("version")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    return match.group(1) if match else None


def test_every_sdk_manifest_declares_a_version_policy() -> None:
    """A new SDK must state whether it tracks the platform or runs its own line."""
    classified = set(SDK_TRACKS_PLATFORM) | set(SDK_INDEPENDENT)
    unclassified = sorted(set(_sdk_manifests()) - classified)
    assert unclassified == [], (
        f"unclassified SDK manifest(s) — add each to SDK_TRACKS_PLATFORM or SDK_INDEPENDENT in this test with the reason: {unclassified}"
    )
    assert not (set(SDK_TRACKS_PLATFORM) & set(SDK_INDEPENDENT)), "an SDK cannot be both platform-tracking and independent"


def test_platform_tracking_sdks_match_the_canonical_version() -> None:
    cva = _load_script("check_version_alignment.py")
    version = cva.canonical_version()
    drift = []
    for rel in SDK_TRACKS_PLATFORM:
        path = ROOT / rel
        assert path.exists(), f"{rel} is classified as platform-tracking but does not exist"
        found = _manifest_version(path)
        if found != version:
            drift.append(f"{rel}: {found} (expected platform version {version})")
    assert drift == [], "platform-tracking SDK version drift:\n" + "\n".join(drift)


def test_platform_tracking_sdks_are_owned_by_the_release_bump() -> None:
    """bump-version.py must rewrite every platform-tracking SDK manifest."""
    bump = _load_script("bump-version.py")
    managed = {rel for rel, _pattern, _template in bump.VERSION_LOCATIONS}
    missing = sorted(set(SDK_TRACKS_PLATFORM) - managed)
    assert missing == [], f"platform-tracking SDK(s) not in bump-version.py VERSION_LOCATIONS: {missing}"


def test_sdk_version_policy_entries_are_documented() -> None:
    """Silencing this gate requires writing down why, not just adding a path."""
    for rel, reason in {**SDK_TRACKS_PLATFORM, **SDK_INDEPENDENT}.items():
        assert len(reason.strip()) >= 60, f"{rel}: version-policy rationale is too thin to review"


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
