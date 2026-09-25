"""Release storefront contracts for concise onboarding and sanitized proof."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from scripts import check_release_consistency
from scripts.render_docker_storefront import render_published_readme

ROOT = Path(__file__).resolve().parents[1]


_MIRRORED_PATHS = (
    *check_release_consistency.PRODUCT_SCREENSHOT_INPUTS,
    "ui",
    "docs/images",
)


@pytest.fixture(scope="module")
def _repo_mirror(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A git-indexed copy of the tracked capture inputs, private to this worker.

    The capture-inputs digest reads `git ls-files` plus on-disk bytes, so the
    mirror carries its own index. Mutating tests edit the mirror, never the
    checkout: parallel workers (and `npm ci` in the same tree) keep reading
    the committed files.
    """
    mirror = tmp_path_factory.mktemp("capture-inputs-mirror")
    tracked = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT}", "ls-files", "-z", "--", *_MIRRORED_PATHS],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    for relative in filter(None, tracked.decode("utf-8").split("\0")):
        source = ROOT / relative
        if not source.is_file():
            continue
        target = mirror / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    git = ["git", "-c", f"safe.directory={mirror}", "-c", "core.hooksPath=/dev/null"]
    subprocess.run([*git, "init", "-q"], cwd=mirror, check=True)
    subprocess.run([*git, "add", "-A"], cwd=mirror, check=True)
    return mirror


@pytest.fixture
def mirror(_repo_mirror: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(check_release_consistency, "ROOT", _repo_mirror)
    monkeypatch.setattr(check_release_consistency, "PRODUCT_SCREENSHOTS", _repo_mirror / "docs" / "images" / "product-screenshots.json")
    return _repo_mirror


@contextlib.contextmanager
def _mutate_repo_file(path: Path, transform: Callable[[bytes], bytes]) -> Iterator[None]:
    """Temporarily mutate a mirrored capture input and restore it after."""
    assert ROOT not in path.resolve().parents, f"refusing to mutate a tracked checkout file: {path}"
    original = path.read_bytes()
    try:
        path.write_bytes(transform(original))
        yield
    finally:
        path.write_bytes(original)


def _bump_json_string_field(section: str, name: str) -> Callable[[bytes], bytes]:
    def transform(original: bytes) -> bytes:
        data = json.loads(original)
        assert name in data.get(section, {}), f"fixture assumption stale: {name!r} is no longer in ui/package.json {section!r}"
        data[section][name] = f"{data[section][name]}-test-bump"
        return (json.dumps(data, indent=2) + "\n").encode("utf-8")

    return transform


def test_release_storefront_context_distinguishes_candidate_from_published_release() -> None:
    version = check_release_consistency._load_version()
    previous_version = "0.0.0"
    assert not check_release_consistency._requires_published_storefront(version, {})
    assert not check_release_consistency._is_matching_release_tag(
        version, {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": f"v{previous_version}"}
    )
    assert check_release_consistency._is_matching_release_tag(version, {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": f"v{version}"})
    assert check_release_consistency._requires_published_storefront(version, {"AGENT_BOM_RELEASE_FINALIZE": "true"})


def test_release_workflow_promotes_candidate_only_in_external_storefront_render(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    version = check_release_consistency._load_version()
    neutral = f"| `{version}` | Version used by the examples below; verify registry availability before pinning |\n"
    rendered = render_published_readme(neutral, version)
    assert neutral not in rendered
    assert f"| `{version}` | Current stable version (pinned) |" in rendered

    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    monkeypatch.setenv("GITHUB_REF_NAME", f"v{version}")
    check_release_consistency._assert_docker_storefront_state(version)

    monkeypatch.setenv("AGENT_BOM_RELEASE_FINALIZE", "1")
    with pytest.raises(SystemExit):
        check_release_consistency._assert_docker_storefront_state(version)
    published = tmp_path / "DOCKER_HUB_README.published.md"
    published.write_text(rendered)
    monkeypatch.setenv("AGENT_BOM_DOCKER_README_PATH", str(published))
    check_release_consistency._assert_docker_storefront_state(version)

    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "scripts/render_docker_storefront.py" in workflow
    assert 'AGENT_BOM_DOCKER_README_PATH="$PUBLISHED_README"' in workflow
    assert 'DESCRIPTION=$(jq -Rs . < "$PUBLISHED_README")' in workflow


def test_release_manifest_covers_dark_light_and_mobile_product_proof() -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    entries = {entry["path"]: entry for entry in manifest["screenshots"]}

    required = {
        "dashboard-live.png": "dark desktop",
        "dashboard-light-live.png": "light desktop",
        "dashboard-mobile-live.png": "dark mobile",
        "security-graph-live.png": "dark desktop",
        "security-graph-light-live.png": "light desktop",
        "security-graph-mobile-live.png": "dark mobile",
    }
    for path, presentation in required.items():
        assert path in entries
        assert entries[path]["presentation"] == presentation
        assert (ROOT / "docs/images" / path).is_file()

    note = str(manifest["capture_note"])
    assert "deterministic" in note.lower()
    assert "external" in note.lower()


def test_release_manifest_carries_reproducible_sanitized_provenance() -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))

    assert re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"])
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["capture_inputs_sha256"])
    assert manifest["source_tree"] == "clean"
    assert "private infrastructure" in manifest["capture_note"].lower()

    for entry in manifest["screenshots"]:
        screenshot = ROOT / "docs" / "images" / entry["path"]
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", entry["sha256"])
        actual = hashlib.sha256(screenshot.read_bytes()).hexdigest()
        assert entry["sha256"] == f"sha256:{actual}"

    paths = {entry["path"] for entry in manifest["screenshots"]}
    entries = {entry["path"]: entry for entry in manifest["screenshots"]}
    assert {"agent-lifecycle-live.png", "jobs-pipeline-live.png"} <= paths
    assert {"correlation-receipts-live.png", "correlation-path-live.png"} <= paths
    assert {"remediation-live.png", "remediation-light-live.png", "remediation-mobile-live.png"} <= paths

    lab_digest = (ROOT / "examples/reference-evidence-lab/generated/correlation-proof.sha256").read_text(encoding="utf-8").strip()
    for path in ("correlation-receipts-live.png", "correlation-path-live.png"):
        assert entries[path]["evidence_sha256"] == lab_digest
        assert entries[path]["correlation_manifest_sha256"].startswith("sha256:")


def test_release_manifest_rejects_a_future_visible_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    manifest["screenshots"][0]["visible_version"] = "999.0.0"
    candidate = tmp_path / "product-screenshots.json"
    candidate.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(check_release_consistency, "PRODUCT_SCREENSHOTS", candidate)

    with pytest.raises(SystemExit):
        check_release_consistency._assert_product_screenshots_current(check_release_consistency._load_version())
    assert "newer than the release" in capsys.readouterr().err


@pytest.mark.parametrize("different_owner", [False, True])
def test_release_manifest_rejects_capture_input_hash_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], different_owner: bool
) -> None:
    if different_owner:
        # Container runners can mount a checkout owned by the host user while
        # tests isolate HOME. Trust only this read-only guard's known checkout.
        monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "empty-git-config"))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    manifest["capture_inputs_sha256"] = f"sha256:{'0' * 64}"
    candidate = tmp_path / "product-screenshots.json"
    candidate.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(check_release_consistency, "PRODUCT_SCREENSHOTS", candidate)

    with pytest.raises(SystemExit):
        check_release_consistency._assert_product_screenshots_current(check_release_consistency._load_version())
    assert "capture inputs changed" in capsys.readouterr().err


def test_capture_runbook_matches_the_local_authenticated_release_workflow() -> None:
    """The published runbook must stay executable as auth and capture contracts evolve."""
    runbook = (ROOT / "docs/CAPTURE.md").read_text(encoding="utf-8")
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    backend_smoke = runbook.split("Backend-connected release evidence", 1)[1].split("## Per-screenshot scope", 1)[0]

    assert f"Inspect all {len(manifest['screenshots'])} PNGs" in runbook
    assert "`CAPTURE_BASE_URL` is not supported" in runbook
    assert "export CAPTURE_BASE_URL" not in runbook
    assert '--api-key "$CAPTURE_API_KEY"' in backend_smoke
    assert "Authorization: Bearer $CAPTURE_API_KEY" in backend_smoke
    assert "--allow-insecure-no-auth" not in runbook


def test_floating_refresh_preserves_published_storefront_status() -> None:
    workflow = (ROOT / ".github/workflows/refresh-latest-container.yml").read_text()
    assert "scripts/render_docker_storefront.py" in workflow
    assert '--version "${{ steps.release.outputs.version }}"' in workflow
    assert 'AGENT_BOM_DOCKER_README_PATH="$PUBLISHED_README"' in workflow
    assert 'DESCRIPTION=$(jq -Rs . < "$PUBLISHED_README")' in workflow
    assert "DESCRIPTION=$(jq -Rs . < DOCKER_HUB_README.md)" not in workflow


# ---------------------------------------------------------------------------
# Product-screenshot capture-input scoping.
#
# PRODUCT_SCREENSHOT_INPUTS used to be the whole "ui" directory, so a pure
# devDependency bump (e.g. PR #5319, @types/node 26.6.1 -> 26.6.2) tripped
# "Version Alignment" CI even though a TypeScript-only type-definitions
# package can never affect a rendered pixel. These tests pin the narrowed
# scope: a devDependency/lockfile/test/tooling-config change must NOT move
# the digest, while a `dependencies` bump or a real UI source change MUST.
# ---------------------------------------------------------------------------


def test_capture_input_digest_ignores_a_dev_dependency_only_package_json_bump(mirror: Path) -> None:
    package_json = mirror / "ui" / "package.json"
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(package_json, _bump_json_string_field("devDependencies", "@types/node")):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    after = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during == before
    assert after == before


def test_assert_product_screenshots_current_tolerates_a_dev_dependency_only_bump(mirror: Path) -> None:
    """End-to-end repro of PR #5319: a devDependency bump must not fail the gate."""
    package_json = mirror / "ui" / "package.json"
    version = check_release_consistency._load_version()
    with _mutate_repo_file(package_json, _bump_json_string_field("devDependencies", "@types/node")):
        check_release_consistency._assert_product_screenshots_current(version)  # must not raise


def test_capture_input_digest_still_moves_for_a_direct_dependency_bump(mirror: Path) -> None:
    """The critical regression guard: `dependencies` (not `devDependencies`) must still trip the gate."""
    package_json = mirror / "ui" / "package.json"
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(package_json, _bump_json_string_field("dependencies", "next")):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during != before


def test_assert_product_screenshots_current_still_rejects_a_direct_dependency_bump(
    mirror: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    package_json = mirror / "ui" / "package.json"
    version = check_release_consistency._load_version()
    with _mutate_repo_file(package_json, _bump_json_string_field("dependencies", "next")):
        with pytest.raises(SystemExit):
            check_release_consistency._assert_product_screenshots_current(version)
    assert "capture inputs changed" in capsys.readouterr().err


def test_capture_input_digest_ignores_package_lock_json_changes(mirror: Path) -> None:
    lockfile = mirror / "ui" / "package-lock.json"
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(lockfile, lambda original: original + b"\n"):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during == before


@pytest.mark.parametrize(
    "relative_path",
    [
        "ui/eslint.config.mjs",
        "ui/vitest.config.ts",
        "ui/playwright.config.ts",
    ],
)
def test_capture_input_digest_ignores_tooling_config(mirror: Path, relative_path: str) -> None:
    target = mirror / relative_path
    assert target.is_file(), f"fixture assumption stale: {relative_path} no longer exists"
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(target, lambda original: original + b"\n"):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during == before


def test_capture_input_digest_ignores_test_files(mirror: Path) -> None:
    test_files = sorted((mirror / "ui" / "tests").glob("*.test.tsx"))
    assert test_files, "fixture assumption stale: ui/tests/*.test.tsx no longer exists"
    target = test_files[0]
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(target, lambda original: original + b"\n"):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during == before

    e2e_files = sorted((mirror / "ui" / "e2e").glob("*.spec.ts"))
    assert e2e_files, "fixture assumption stale: ui/e2e/*.spec.ts no longer exists"
    target = e2e_files[0]
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(target, lambda original: original + b"\n"):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during == before


def test_capture_input_digest_still_moves_for_a_real_component_source_change(mirror: Path) -> None:
    target = mirror / "ui" / "components" / "activity-feed.tsx"
    assert target.is_file(), "fixture assumption stale: ui/components/activity-feed.tsx no longer exists"
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(target, lambda original: original + b"\n// regression-probe\n"):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during != before


def test_capture_input_digest_still_moves_for_a_public_asset_change(mirror: Path) -> None:
    public_files = sorted((mirror / "ui" / "public").rglob("*"))
    candidates = [p for p in public_files if p.is_file()]
    assert candidates, "fixture assumption stale: ui/public has no files"
    target = candidates[0]
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(target, lambda original: original + b"\x00"):
        during = check_release_consistency._compute_product_screenshot_inputs_digest()
    assert during != before


def test_capture_input_digest_matches_the_javascript_mirror() -> None:
    """scripts/check_release_consistency.py and ui/scripts/product-proof-provenance.mjs
    must compute byte-identical digests, since the recorded manifest value is
    produced by the JS side and verified by the Python side."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in this environment")
    python_digest = check_release_consistency._compute_product_screenshot_inputs_digest()
    script = (
        "import('./ui/scripts/product-proof-provenance.mjs')"
        ".then(m => m.computeCaptureInputsDigest(process.cwd()))"
        ".then(d => { process.stdout.write(d); });"
    )
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == python_digest


def test_release_manifest_capture_inputs_digest_is_current() -> None:
    """The committed manifest's capture_inputs_sha256 must already reflect the
    narrowed input scope — regenerated via `npm run capture:inputs-digest`,
    never hand-edited."""
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    assert manifest["capture_inputs_sha256"] == check_release_consistency._compute_product_screenshot_inputs_digest()


@pytest.mark.parametrize(
    "section,name", [("devDependencies", "tailwindcss"), ("devDependencies", "lightningcss"), ("overrides", "postcss")]
)
def test_capture_digest_tracks_rendering_toolchain(mirror: Path, section, name):
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(mirror / "ui/package.json", _bump_json_string_field(section, name)):
        assert check_release_consistency._compute_product_screenshot_inputs_digest() != before


def test_capture_digest_tracks_resolved_runtime_dependency(mirror: Path):
    def change(original):
        data = json.loads(original)
        data["packages"]["node_modules/next"]["version"] = "99.0.0"
        return json.dumps(data).encode()

    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(mirror / "ui/package-lock.json", change):
        assert check_release_consistency._compute_product_screenshot_inputs_digest() != before


def test_capture_digest_tracks_typescript_build_config(mirror: Path):
    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(mirror / "ui/tsconfig.json", lambda content: content + b"\n"):
        assert check_release_consistency._compute_product_screenshot_inputs_digest() != before


def test_capture_digest_ignores_only_node_types_lock_entry(mirror: Path):
    def change(original):
        data = json.loads(original)
        data["packages"]["node_modules/@types/node"]["version"] = "99.0.0"
        data["packages"][""]["devDependencies"]["@types/node"] = "99.0.0"
        return json.dumps(data).encode()

    before = check_release_consistency._compute_product_screenshot_inputs_digest()
    with _mutate_repo_file(mirror / "ui/package-lock.json", change):
        assert check_release_consistency._compute_product_screenshot_inputs_digest() == before


def test_capture_input_mirror_digest_matches_the_checkout(_repo_mirror: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = check_release_consistency._compute_product_screenshot_inputs_digest()
    monkeypatch.setattr(check_release_consistency, "ROOT", _repo_mirror)
    assert check_release_consistency._compute_product_screenshot_inputs_digest() == real


def test_mutation_helper_refuses_tracked_checkout_files() -> None:
    package_json = ROOT / "ui" / "package.json"
    before = package_json.read_bytes()
    with pytest.raises(AssertionError, match="refusing to mutate"):
        with _mutate_repo_file(package_json, lambda original: original + b"\n"):
            pass
    assert package_json.read_bytes() == before
