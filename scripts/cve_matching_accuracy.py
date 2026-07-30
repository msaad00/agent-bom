#!/usr/bin/env python3
"""Measure CVE range-matching accuracy against advisory-declared ground truth.

The scanner's core promise is that a vulnerable version is reported and a fixed
one is not. Until now nothing measured that: a defect could only surface as a
bug report, which is how a multi-window parsing error survived in two separate
parsers while every test passed.

The oracle needs no hand labelling. Many OSV advisories carry BOTH an explicit
``versions[]`` list and a ``ranges[]`` block describing the same fact. The list
is the advisory's own statement of which releases are affected, so replaying it
through the range matcher gives labelled data for free:

* a version in ``versions[]`` that the matcher calls unaffected is a FALSE
  NEGATIVE — a missed vulnerability, the failure mode that matters most;
* a version outside it that the matcher calls affected is a FALSE POSITIVE —
  noise that erodes trust in the queue.

Advisories with no ``ranges`` are skipped: there is nothing to evaluate.
Advisories whose declared versions are all uncomparable for their ecosystem are
counted separately rather than scored, so a comparator gap is visible instead of
being laundered into the headline number.

Run:
    python scripts/cve_matching_accuracy.py                 # committed corpus
    python scripts/cve_matching_accuracy.py --check         # CI gate
    python scripts/cve_matching_accuracy.py --write         # refresh baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

CORPUS = ROOT / "tests" / "fixtures" / "cve_accuracy_corpus.json"
BASELINE = ROOT / "docs" / "CVE_MATCHING_ACCURACY.json"


@dataclass
class Outcome:
    """Scored result over one corpus."""

    advisories: int = 0
    evaluated: int = 0
    skipped_no_ranges: int = 0
    skipped_uncomparable: int = 0
    skipped_unsound_oracle: int = 0
    multi_window: int = 0
    true_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0
    false_positive: int = 0
    misses: list[str] = field(default_factory=list)
    spurious: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        actual = self.true_positive + self.false_negative
        return self.true_positive / actual if actual else 1.0

    @property
    def precision(self) -> float:
        flagged = self.true_positive + self.false_positive
        return self.true_positive / flagged if flagged else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "advisories": self.advisories,
            "evaluated": self.evaluated,
            "skipped_no_ranges": self.skipped_no_ranges,
            "skipped_uncomparable": self.skipped_uncomparable,
            "skipped_unsound_oracle": self.skipped_unsound_oracle,
            "multi_window_advisories": self.multi_window,
            "true_positive": self.true_positive,
            "false_negative": self.false_negative,
            "true_negative": self.true_negative,
            "false_positive": self.false_positive,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
        }


_ECOSYSTEM_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER", ""})


def _git_tag_contaminated(block: dict) -> bool:
    """True when ``versions[]`` is a git-tag walk, not an ecosystem statement.

    A ``GIT`` range beginning at ``introduced: 0`` makes OSV's importer write
    every tag reachable before the fix commit into ``versions[]``. When the same
    block ALSO carries an ecosystem range with a non-zero lower bound, the two
    disagree about where the vulnerability starts, and the enumeration names
    releases the advisory's own ecosystem range excludes: PYSEC-2015-17 lists
    ``requests v0.2.0`` beside an ECOSYSTEM range introduced at 2.1.0, while NVD
    scopes CVE-2015-2296 to "2.1.0 through 2.5.3".

    Such a block cannot label anything — counting its tags as affected would
    demand a FALSE POSITIVE to score full recall — so it is skipped and reported
    rather than scored. The test is a property of the DATA (two lower bounds in
    one block); it never consults the matcher's answer, so it cannot be tuned to
    flatter the score.
    """
    ranges = block.get("ranges") or []
    git_from_zero = any(
        (rng.get("type") or "") == "GIT" and any(event.get("introduced") == "0" for event in rng.get("events") or []) for rng in ranges
    )
    if not git_from_zero:
        return False
    return any(
        (rng.get("type") or "") in _ECOSYSTEM_RANGE_TYPES
        and any(event.get("introduced") not in (None, "0") for event in rng.get("events") or [])
        for rng in ranges
    )


def _sound_negatives(block: dict) -> list[str]:
    """Versions the advisory itself proves are NOT affected.

    Absence from ``versions[]`` does not mean unaffected — that list enumerates
    known releases, while a range can cover versions it never names. So the only
    defensible negatives come from the range's own upper bounds: a ``fixed``
    value is by definition the first release that is not vulnerable.

    Using anything looser would make precision a measure of the test data rather
    than of the matcher.
    """
    declared = {str(v) for v in (block.get("versions") or [])}
    negatives: set[str] = set()
    for rng in block.get("ranges") or []:
        for event in rng.get("events") or []:
            fixed = event.get("fixed")
            if fixed and str(fixed) not in declared:
                negatives.add(str(fixed))
    return sorted(negatives)


def score(entries: list[dict]) -> Outcome:
    from agent_bom.scanners.package_scan import _is_version_affected

    out = Outcome()
    for entry in entries:
        out.advisories += 1
        vuln = entry["advisory"]
        if any(
            sum(1 for ev in rng.get("events") or [] if "introduced" in ev) > 1
            for blk in vuln.get("affected") or []
            for rng in blk.get("ranges") or []
        ):
            out.multi_window += 1
        affected_blocks = vuln.get("affected") or []
        if not any(block.get("ranges") for block in affected_blocks):
            out.skipped_no_ranges += 1
            continue

        scored_any = False
        unsound_any = False
        for block in affected_blocks:
            package = block.get("package") or {}
            name = package.get("name") or ""
            ecosystem = package.get("ecosystem") or ""
            declared = [str(v) for v in (block.get("versions") or [])]
            if not (name and declared and block.get("ranges")):
                continue
            if _git_tag_contaminated(block):
                unsound_any = True
                out.skipped_unsound_oracle += 1
                continue

            # Score against a RANGES-ONLY copy. ``_is_version_affected`` checks
            # the explicit ``versions`` list before the ranges, so leaving it in
            # would short-circuit every case on the very list the ground truth
            # came from — the benchmark would report perfect accuracy while the
            # range logic went completely unexercised. Verified by mutation:
            # with the list present, reintroducing the multi-window collapse bug
            # did not move the score at all.
            probe = {
                "id": vuln.get("id"),
                "affected": [{"package": b.get("package", {}), "ranges": b.get("ranges", [])} for b in affected_blocks],
            }

            for version in declared:
                scored_any = True
                if _is_version_affected(probe, name, version, ecosystem):
                    out.true_positive += 1
                else:
                    out.false_negative += 1
                    out.misses.append(f"{vuln.get('id')} {ecosystem}:{name}@{version}")

            for candidate in _sound_negatives(block):
                if _is_version_affected(probe, name, candidate, ecosystem):
                    out.false_positive += 1
                    out.spurious.append(f"{vuln.get('id')} {ecosystem}:{name}@{candidate} (advisory says fixed here)")
                else:
                    out.true_negative += 1

        if scored_any:
            out.evaluated += 1
        elif not unsound_any:
            # Only a real comparator gap belongs in this bucket; an advisory
            # skipped for an unsound oracle is already counted above.
            out.skipped_uncomparable += 1
    return out


def _load_corpus() -> list[dict]:
    if not CORPUS.exists():
        raise SystemExit(f"corpus not found: {CORPUS}\nGenerate it with scripts/build_cve_accuracy_corpus.py")
    return json.loads(CORPUS.read_text(encoding="utf-8"))["entries"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail when accuracy regresses below the recorded baseline")
    parser.add_argument("--write", action="store_true", help="record current results as the baseline")
    args = parser.parse_args()

    result = score(_load_corpus())
    payload = result.to_dict()

    print(f"advisories: {payload['advisories']}  evaluated: {payload['evaluated']}")
    print(
        f"  skipped (no ranges): {payload['skipped_no_ranges']}"
        f"  (uncomparable): {payload['skipped_uncomparable']}"
        f"  (unsound oracle): {payload['skipped_unsound_oracle']}"
    )
    print(f"  recall:    {payload['recall']:.4f}  ({payload['true_positive']} found / {payload['false_negative']} missed)")
    print(f"  precision: {payload['precision']:.4f}  ({payload['false_positive']} spurious)")
    print(f"  f1:        {payload['f1']:.4f}")
    for miss in result.misses[:10]:
        print(f"    MISSED: {miss}")
    for extra in result.spurious[:10]:
        print(f"    SPURIOUS: {extra}")

    if args.write:
        BASELINE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote baseline {BASELINE.relative_to(ROOT)}")
        return 0

    if args.check:
        if not BASELINE.exists():
            print(f"ERROR: no baseline at {BASELINE.relative_to(ROOT)}; run --write", file=sys.stderr)
            return 1
        prior = json.loads(BASELINE.read_text(encoding="utf-8"))
        failed = False
        for metric in ("recall", "precision"):
            if payload[metric] + 1e-9 < prior[metric]:
                print(f"ERROR: {metric} regressed {prior[metric]:.4f} -> {payload[metric]:.4f}", file=sys.stderr)
                failed = True
        # A corpus that loses its multi-window advisories silently loses the
        # ability to detect a window-collapse regression, which is the exact
        # defect this gate exists for. Verified by mutation: with 1 such
        # advisory the score does not move; with 22 it drops to 0.9823.
        if payload["multi_window_advisories"] < prior.get("multi_window_advisories", 0):
            print(
                f"ERROR: multi-window coverage dropped "
                f"{prior.get('multi_window_advisories')} -> {payload['multi_window_advisories']}; "
                "the corpus can no longer detect a window-collapse regression",
                file=sys.stderr,
            )
            failed = True
        # Skipping is how the gate stays honest about data it cannot label, but
        # it is also how a corpus could be quietly hollowed out. Pin it.
        if payload["skipped_unsound_oracle"] > prior.get("skipped_unsound_oracle", 0):
            print(
                f"ERROR: unsound-oracle skips grew "
                f"{prior.get('skipped_unsound_oracle', 0)} -> {payload['skipped_unsound_oracle']}; "
                "more of the corpus is going unscored",
                file=sys.stderr,
            )
            failed = True
        if payload["evaluated"] < prior["evaluated"]:
            print(
                f"ERROR: evaluated advisories dropped {prior['evaluated']} -> {payload['evaluated']}; coverage must not shrink silently",
                file=sys.stderr,
            )
            failed = True
        return 1 if failed else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
