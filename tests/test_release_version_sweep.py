"""Contract for the derived version sweep in `scripts/check_release_consistency.py`.

`bump-version.py` (the writer) and `check_release_consistency.py` (the checker)
were both hand-maintained lists. A version-bearing artifact in neither list is
written by nobody and checked by nobody, which is how `sdks/python/pyproject.toml`
sat at 0.92.0 against a 0.100.0 platform. The sweep finds such artifacts by shape,
so these tests pin that it stays structural and fails closed.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_release_consistency.py"
BUMP = ROOT / "scripts" / "bump-version.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_release_consistency", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


crc = _load()


def _release_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    assert match
    return match.group(1)


class TestTheRepositoryItself:
    def test_no_artifact_drifts_from_the_release_version(self):
        problems = crc.sweep_version_drift(_release_version())
        assert problems == [], "version drift:\n" + "\n".join(problems)

    def test_the_python_sdk_tracks_the_platform_release(self):
        """The exact artifact that drifted; it is an alias for the shipped client."""
        sdk = (ROOT / "sdks" / "python" / "pyproject.toml").read_text(encoding="utf-8")
        assert f'version = "{_release_version()}"' in sdk

    def test_the_writer_also_owns_the_python_sdk(self):
        """A checker without a matching writer just relocates the manual step."""
        assert "sdks/python/pyproject.toml" in BUMP.read_text(encoding="utf-8")


class TestTheSweepIsStructural:
    def test_drift_is_detected_for_an_arbitrary_version(self):
        """Sweeping against a version nothing matches must report, not pass."""
        problems = crc.sweep_version_drift("9.9.9")
        assert problems, "sweeping against an impossible version found nothing — the sweep is not reading files"

    def test_every_sweep_entry_is_a_glob_not_a_filename(self):
        for glob, _pattern, _label in crc.VERSION_SWEEP:
            assert "*" in glob, f"{glob!r} names a single file; a new sibling would escape the sweep"

    def test_compose_profiles_are_covered_by_a_glob(self):
        globs = [glob for glob, _p, _l in crc.VERSION_SWEEP]
        assert any("docker-compose" in glob for glob in globs)

    def test_sdk_packages_are_covered_by_a_glob(self):
        globs = [glob for glob, _p, _l in crc.VERSION_SWEEP]
        assert any(glob.startswith("sdks/") for glob in globs)


class TestPackageJsonPatternIsSafeAndScoped:
    """The npm pattern must find the top-level version and nothing else — fast.

    It originally read `(?:[^{}]|\\n)*?`. A negated character class already
    matches newline in Python, so that alternation let the engine consume one
    character two ways and backtracking went exponential (CodeQL ReDoS, HIGH).
    """

    @staticmethod
    def _pattern():
        return dict((glob, pattern) for glob, pattern, _label in crc.VERSION_SWEEP)["sdks/*/package.json"]

    def test_top_level_version_is_matched(self):
        package = '{\n  "name": "@agent-bom/client",\n  "version": "1.2.3"\n}\n'
        assert {m.group(1) for m in self._pattern().finditer(package)} == {"1.2.3"}

    def test_nested_dependency_version_is_not_matched(self):
        """A dependency's version must never be mistaken for the package's own."""
        package = '{\n  "name": "x",\n  "dependencies": {\n    "left-pad": "9.9.9",\n    "dep": { "version": "8.8.8" }\n  }\n}\n'
        assert self._pattern().findall(package) == []

    def test_nested_version_after_a_closed_object_is_not_matched(self):
        """Once any brace appears, the brace-free run can no longer reach past it."""
        package = '{\n  "engines": { "node": ">=20" },\n  "version": "7.7.7"\n}\n'
        assert self._pattern().findall(package) == []

    def test_real_sdk_manifests_match_their_declared_version(self):
        for manifest in sorted((ROOT / "sdks").glob("*/package.json")):
            text = manifest.read_text(encoding="utf-8")
            declared = json.loads(text)["version"]
            assert {m.group(1) for m in self._pattern().finditer(text)} == {declared}, manifest

    def test_pathological_input_completes_promptly(self):
        """A brace followed by many newlines and no version must not blow up."""
        payload = "{" + "\n" * 4000
        start = time.perf_counter()
        assert self._pattern().search(payload) is None
        assert time.perf_counter() - start < 1.0

    def test_no_sweep_pattern_repeats_a_negated_class_alternated_with_newline(self):
        """Pin the whole class, not just the one instance that was reported."""
        for glob, pattern, _label in crc.VERSION_SWEEP:
            assert not re.search(r"\(\?:\[\^[^\]]*\]\|\\n\)", pattern.pattern), glob


class TestIndependentVersionsAreDeclared:
    def test_every_exemption_carries_a_reason(self):
        for path, reason in crc.INDEPENDENTLY_VERSIONED.items():
            assert len(reason) > 20, f"{path} is exempt without an explanation"

    def test_every_exempt_path_exists(self):
        """A stale exemption silently un-guards nothing and hides a typo."""
        for path in crc.INDEPENDENTLY_VERSIONED:
            assert (ROOT / path).is_file(), f"{path} is exempt but does not exist"

    def test_exemptions_are_exact_paths_not_globs(self):
        """A glob here would re-open the hole the sweep closes."""
        for path in crc.INDEPENDENTLY_VERSIONED:
            assert "*" not in path

    def test_removing_an_exemption_surfaces_that_artifact(self, monkeypatch):
        monkeypatch.setattr(crc, "INDEPENDENTLY_VERSIONED", {})
        problems = crc.sweep_version_drift(_release_version())
        assert any("sdks/typescript" in problem for problem in problems)
