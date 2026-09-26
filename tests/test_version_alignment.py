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
    """Every managed reference is aligned: copy-paste refs to PUBLISHED_VERSION, source-built pins to pyproject."""
    cva = _load_script("check_version_alignment.py")
    version = cva.canonical_version()
    drift = cva.find_drift(version, published=cva.published_version())
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


def test_screenshot_manifest_release_version_is_owned_by_the_release_bump() -> None:
    bump = _load_script("bump-version.py")
    entries = [(pattern, template) for rel, pattern, template in bump.DOC_TEST_LOCATIONS if rel == "docs/images/product-screenshots.json"]
    assert len(entries) == 1
    pattern, template = entries[0]
    payload = '{"release_version":"0.101.0","screenshots":[{"visible_version":"0.101.0"}]}'
    rewritten, count = pattern.subn(template.format(v="0.102.0"), payload)
    assert count == 1
    assert '"release_version":"0.102.0"' in rewritten
    assert '"visible_version":"0.101.0"' in rewritten


def test_consumer_precommit_revs_are_owned_by_the_published_sweep() -> None:
    cva = _load_script("check_version_alignment.py")
    payload = "  - repo: https://github.com/msaad00/agent-bom\n    rev: v0.101.0\n"
    for path in ("README.md", "docs/DEPLOYMENT.md", ".pre-commit-hooks.yaml"):
        drift = cva.scan_text(path, payload, "0.103.0", published="0.102.0")
        assert len(drift) == 1 and "expected 0.102.0" in drift[0], (path, drift)


def test_released_artifact_commands_are_owned_by_the_published_bump() -> None:
    bump = _load_script("bump-version.py")
    managed = {rel for rel, _pattern, _template in bump.PUBLISHED_LOCATIONS}
    source_managed = {rel for rel, _pattern, _template in bump.VERSION_LOCATIONS + bump.DOC_TEST_LOCATIONS}
    for rel in (
        "site-docs/deployment/control-plane-helm.md",
        "site-docs/deployment/airgapped-image-bundle.md",
        "site-docs/deployment/aws-company-rollout.md",
        "docs/RELEASE_VERIFICATION.md",
    ):
        assert rel in managed, rel
        assert rel not in source_managed, f"{rel} would be rewritten to the unreleased source version"


def test_prepping_a_release_leaves_copy_paste_surfaces_on_the_published_version(tmp_path, monkeypatch) -> None:
    """The original defect: bumping main to the next version rewrote Action/image pins to a tag that 404s."""
    bump = _load_script("bump-version.py")
    cva = sys.modules["check_version_alignment"] = _load_script("check_version_alignment.py")
    (tmp_path / "PUBLISHED_VERSION").write_text("0.105.0\n")
    (tmp_path / "pyproject.toml").write_text('version = "0.105.0"\n')
    docs = tmp_path / "docs"
    docs.mkdir()
    guide = docs / "START_HERE.md"
    guide.write_text("- uses: msaad00/agent-bom@v0.105.0\n")
    helm = docs / "helm.md"
    helm.write_text("  --version 0.105.0 \\\n")
    monkeypatch.setattr(cva, "ROOT", tmp_path)
    monkeypatch.setattr(cva, "PYPROJECT", tmp_path / "pyproject.toml")
    monkeypatch.setattr(cva, "PUBLISHED_VERSION_FILE", tmp_path / "PUBLISHED_VERSION")
    monkeypatch.setattr(cva, "SCAN_ROOTS", (docs,))
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "_release_tags", lambda: set())
    monkeypatch.setattr(bump, "ROOT", tmp_path)
    monkeypatch.setattr(bump, "_load_alignment", lambda: cva)
    monkeypatch.setattr(bump, "VERSION_LOCATIONS", [])
    monkeypatch.setattr(bump, "DOC_TEST_LOCATIONS", [])
    monkeypatch.setattr(bump, "OPENCLAW_SKILL_PATTERNS", [])
    monkeypatch.setattr(bump, "PUBLISHED_LOCATIONS", [("docs/helm.md", bump.re.compile(r"(--version\s+)\d+\.\d+\.\d+"), r"\g<1>{v}")])

    assert bump.bump("0.106.0") == 0
    assert "@v0.105.0" in guide.read_text()
    assert "--version 0.105.0" in helm.read_text()
    assert (tmp_path / "PUBLISHED_VERSION").read_text().strip() == "0.105.0"

    # VERSION_LOCATIONS is emptied above, so stand in for the pyproject write.
    (tmp_path / "pyproject.toml").write_text('version = "0.106.0"\n')
    assert bump.bump(published="0.106.0") == 0
    assert "@v0.106.0" in guide.read_text()
    assert "--version 0.106.0" in helm.read_text()
    assert (tmp_path / "PUBLISHED_VERSION").read_text().strip() == "0.106.0"

    assert bump.bump(published="0.107.0") == 1, "the published version must never run ahead of the source version"


def test_public_release_pins_are_owned_by_the_release_bump() -> None:
    bump = _load_script("bump-version.py")
    cases = {
        "docs/PUBLISHING.md": "  --expected 0.101.0 \\\n",
    }
    for path, payload in cases.items():
        entries = [(pattern, template) for rel, pattern, template in bump.DOC_TEST_LOCATIONS if rel == path]
        rewritten = payload
        count = 0
        for pattern, template in entries:
            rewritten, matches = pattern.subn(template.format(v="0.102.0", v_underscore="0_102_0"), rewritten)
            count += matches
        assert count == 1, path
        assert "0.102.0" in rewritten, path
        assert "0.101.0" not in rewritten, path


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


# ---------------------------------------------------------------------------
# Published-version split
#
# main is prepped as the NEXT release before it is tagged. Copy-paste surfaces
# (Action refs, pull-only image pins, pre-commit revs) must keep naming the
# latest PUBLISHED release until it actually exists, or users following main's
# docs pull a tag/image that 404s. Source-built artifacts keep the next version.
# ---------------------------------------------------------------------------


def test_published_version_file_is_semver_and_not_ahead_of_source() -> None:
    cva = _load_script("check_version_alignment.py")
    published = cva.published_version()
    canonical = cva.canonical_version()
    assert cva.parse_semver(published) <= cva.parse_semver(canonical)


def test_action_ref_must_track_published_not_next_version() -> None:
    cva = _load_script("check_version_alignment.py")
    text = "- uses: msaad00/agent-bom@v0.106.0\n"
    drift = cva.scan_text("docs/START_HERE.md", text, "0.106.0", published="0.105.0")
    assert len(drift) == 1 and "0.105.0" in drift[0]
    assert cva.scan_text("docs/START_HERE.md", "- uses: msaad00/agent-bom@v0.105.0\n", "0.106.0", published="0.105.0") == []


def test_pull_only_image_pin_tracks_published_but_source_built_tracks_next() -> None:
    cva = _load_script("check_version_alignment.py")
    pin = "    image: agentbom/agent-bom:0.105.0\n"
    assert cva.scan_text("deploy/docker-compose.pilot.yml", pin, "0.106.0", published="0.105.0") == []
    assert cva.scan_text("deploy/k8s/daemonset.yaml", pin, "0.106.0", published="0.105.0") == []
    assert len(cva.scan_text("deploy/docker-compose.fullstack.yml", pin, "0.106.0", published="0.105.0")) == 1
    built = "    image: agentbom/agent-bom:0.106.0\n"
    assert cva.scan_text("deploy/docker-compose.fullstack.yml", built, "0.106.0", published="0.105.0") == []


def test_consumer_precommit_rev_is_managed_and_tracks_published() -> None:
    cva = _load_script("check_version_alignment.py")
    text = "#   repos:\n#     - repo: https://github.com/msaad00/agent-bom\n#       rev: v0.90.0\n"
    drift = cva.scan_text(".pre-commit-hooks.yaml", text, "0.106.0", published="0.105.0")
    assert len(drift) == 1 and ":3:" in drift[0], drift
    assert (ROOT / ".pre-commit-hooks.yaml") in cva.SCAN_ROOTS


def test_published_version_ahead_of_source_is_drift(monkeypatch) -> None:
    cva = _load_script("check_version_alignment.py")
    monkeypatch.setattr(cva, "SCAN_ROOTS", ())
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "_release_tags", lambda: set())
    drift = cva.find_drift("0.105.0", published="0.106.0")
    assert any("ahead of" in line for line in drift), drift


def test_published_version_must_name_a_real_tag_when_tags_are_known(monkeypatch) -> None:
    cva = _load_script("check_version_alignment.py")
    monkeypatch.setattr(cva, "SCAN_ROOTS", ())
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "_release_tags", lambda: {"v0.104.0", "v0.105.0"})
    assert cva.find_drift("0.106.0", published="0.105.0") == []
    drift = cva.find_drift("0.106.0", published="0.106.0")
    assert any("v0.106.0" in line and "tag" in line for line in drift), drift


def test_every_workflow_running_the_gate_checks_out_all_release_tags() -> None:
    """A checkout holding only the pushed tag makes PUBLISHED_VERSION look unreleased."""
    import yaml

    checked = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, job in (workflow.get("jobs") or {}).items():
            steps = job.get("steps") or []
            if not any("check_version_alignment.py" in str(step.get("run", "")) for step in steps):
                continue
            checkouts = [step.get("with") or {} for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
            assert checkouts, f"{path.name}:{name} runs the gate without a checkout"
            opts = checkouts[0]
            full_history = str(opts.get("fetch-depth", "1")).strip() == "0"
            assert opts.get("fetch-tags") is True or full_history, f"{path.name}:{name} runs the gate without fetching release tags"
            checked.append(f"{path.name}:{name}")
    assert "release.yml:version-guard" in checked, checked


def test_rewrite_moves_each_class_to_its_own_version(tmp_path, monkeypatch) -> None:
    cva = _load_script("check_version_alignment.py")
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    pilot = deploy / "docker-compose.pilot.yml"
    pilot.write_text("image: agentbom/agent-bom:0.90.0\n")
    built = deploy / "docker-compose.fullstack.yml"
    built.write_text("image: agentbom/agent-bom:0.90.0\n")
    guide = tmp_path / "guide.md"
    guide.write_text("uses: msaad00/agent-bom@v0.90.0\n")
    monkeypatch.setattr(cva, "SCAN_ROOTS", (pilot, built, guide))
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "ROOT", tmp_path)
    monkeypatch.setattr(cva, "_release_tags", lambda: set())
    cva.rewrite("0.106.0", published="0.105.0")
    assert "0.105.0" in pilot.read_text()
    assert "0.106.0" in built.read_text()
    assert "@v0.105.0" in guide.read_text()
    assert cva.find_drift("0.106.0", published="0.105.0") == []


def test_source_built_list_matches_compose_reality() -> None:
    """A compose is source-built only if every pinned service really builds from this tree."""
    import yaml

    cva = _load_script("check_version_alignment.py")
    image_pin = cva.MANAGED_PATTERNS[0].regex
    for compose in sorted((ROOT / "deploy").glob("docker-compose*.yml")):
        rel = str(compose.relative_to(ROOT))
        services = (yaml.safe_load(compose.read_text()) or {}).get("services", {})
        pinned = [svc for svc in services.values() if image_pin.search(str(svc.get("image", "")))]
        if not pinned:
            continue
        all_built = all("build" in svc for svc in pinned)
        assert (rel in cva.SOURCE_BUILT) == all_built, f"{rel}: source-built={all_built} but SOURCE_BUILT={rel in cva.SOURCE_BUILT}"
