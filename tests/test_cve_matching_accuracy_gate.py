"""The accuracy gate must be able to fail.

A benchmark that always reports a perfect score is worse than no benchmark: it
manufactures confidence. The first version of this gate did exactly that — it
scored declared versions against the full advisory, but the matcher checks the
explicit ``versions`` list before the ranges, so every case short-circuited on
the same list the ground truth came from. Reintroducing the multi-window
collapse bug did not move the score at all.

These tests pin both properties the gate depends on: it exercises the range
path, and the corpus contains enough multi-window advisories to notice when
that path breaks.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "fixtures" / "cve_accuracy_corpus.json"
BASELINE = ROOT / "docs" / "CVE_MATCHING_ACCURACY.json"


def _load_harness():
    """Import the script by path; scripts/ is not an importable package."""
    target = Path("/tmp") / "cve_matching_accuracy_under_test.py"
    shutil.copyfile(ROOT / "scripts" / "cve_matching_accuracy.py", target)
    spec = importlib.util.spec_from_file_location("cve_matching_accuracy_under_test", target)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclass resolution looks the module up in sys.modules during exec.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def entries() -> list[dict]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))["entries"]


def test_corpus_covers_the_multi_window_shape(entries: list[dict]) -> None:
    """Without these, the gate cannot detect the defect it exists for."""
    multi = sum(
        1
        for entry in entries
        if any(
            sum(1 for event in rng.get("events") or [] if "introduced" in event) > 1
            for block in entry["advisory"].get("affected") or []
            for rng in block.get("ranges") or []
        )
    )
    assert multi >= 10, f"only {multi} multi-window advisories; a collapse regression would go unnoticed"


def test_clean_tree_matches_the_recorded_baseline(entries: list[dict]) -> None:
    harness = _load_harness()
    result = harness.score(entries).to_dict()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    assert result["recall"] >= baseline["recall"]
    assert result["precision"] >= baseline["precision"]
    assert result["false_negative"] == 0, f"missed vulnerable versions: {result['false_negative']}"


def test_the_gate_detects_a_window_collapse_regression(entries: list[dict]) -> None:
    """Mutation test: break the range logic and require the score to fall.

    This is the test that makes the rest of the gate trustworthy.
    """
    harness = _load_harness()
    from agent_bom.scanners import package_scan

    original = package_scan._range_windows
    try:
        # The historical bug: keep only the last window of a multi-window range.
        package_scan._range_windows = lambda events: (original(events) or [])[-1:]
        mutated = harness.score(entries)
    finally:
        package_scan._range_windows = original

    assert mutated.false_negative > 0, (
        "reintroducing the multi-window collapse did not produce a single miss — the gate has no teeth and would pass a real regression"
    )
    assert mutated.recall < 1.0

    restored = harness.score(entries)
    assert restored.false_negative == 0, "harness left mutated state behind"


# ---------------------------------------------------------------------------
# The oracle itself has a failure mode: a GIT range enumerates git TAGS
#
# When an advisory carries a GIT range starting at ``introduced: 0``, OSV's
# importer walks the repository and writes every tag reachable before the fix
# commit into ``versions[]`` — including releases the ECOSYSTEM range explicitly
# excludes. PYSEC-2015-17 lists ``requests v0.2.0`` next to an ECOSYSTEM range
# introduced at 2.1.0, while NVD scopes CVE-2015-2296 to "2.1.0 through 2.5.3".
# Such a block states two different lower bounds, so it cannot label anything:
# scoring it would require a FALSE POSITIVE to reach 100% recall.
# ---------------------------------------------------------------------------


def _contradictory_advisory() -> dict:
    return {
        "id": "TEST-GIT-TAG-CONTAMINATION",
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://example.invalid/r",
                        "events": [{"introduced": "0"}, {"fixed": "3bd8afbff29e50b38f889b2f688785a669b9aafc"}],
                    },
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.1.0"}, {"fixed": "2.6.0"}]},
                ],
                "versions": ["v0.2.0", "2.1.0", "2.5.3"],
            }
        ],
    }


def test_git_tag_enumeration_is_not_accepted_as_ground_truth() -> None:
    """The contaminated block is skipped and counted, not scored."""
    harness = _load_harness()
    out = harness.score([{"advisory": _contradictory_advisory()}])

    assert out.skipped_unsound_oracle == 1
    assert out.evaluated == 0
    assert out.true_positive == 0
    assert out.false_negative == 0, f"a self-contradictory advisory produced labels: {out.misses}"


def test_a_git_range_alone_does_not_disqualify_an_advisory() -> None:
    """Only the CONTRADICTION disqualifies — a GIT range agreeing at 0 is fine."""
    harness = _load_harness()
    advisory = _contradictory_advisory()
    advisory["affected"][0]["ranges"][1]["events"] = [{"introduced": "0"}, {"fixed": "2.6.0"}]
    advisory["affected"][0]["versions"] = ["2.1.0", "2.5.3"]

    out = harness.score([{"advisory": advisory}])
    assert out.skipped_unsound_oracle == 0
    assert out.evaluated == 1
    assert out.true_positive == 2


def test_the_corpus_skip_is_bounded_and_reported(entries: list[dict]) -> None:
    """Skipping must stay a rounding error and must be visible in the payload."""
    harness = _load_harness()
    result = harness.score(entries)
    payload = result.to_dict()

    assert payload["skipped_unsound_oracle"] == 6, "the contaminated set changed — re-derive before trusting the score"
    accounted = result.evaluated + payload["skipped_unsound_oracle"] + payload["skipped_no_ranges"] + payload["skipped_uncomparable"]
    assert accounted >= payload["advisories"]
    # Dropping the contaminated blocks must not cost the corpus its ability to
    # detect a window collapse (the defect this gate exists for).
    assert payload["multi_window_advisories"] >= 10
