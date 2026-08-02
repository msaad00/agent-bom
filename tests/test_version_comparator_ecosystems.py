"""Ecosystem-native version ordering for Packagist/Composer, NuGet and RubyGems.

Each of these ecosystems publishes its own ordering rules, and none of them is
PEP 440. Routing them through ``packaging.Version`` (with a pre-release-tag
strip as the fallback) made whole families of version strings compare EQUAL or
uncomparable, which silently deletes findings: a version sitting inside
``[2.4.5-p1, 2.4.5-p2)`` read as already patched, and every RubyGems
prerelease bound was undecidable.

Expectations here come from the ecosystems' own specifications:

* Packagist/Composer — PHP ``version_compare`` (php.net manual: separators
  ``_ - +`` become ``.``, dots are inserted around non-numerics, and parts are
  ordered ``any other string < dev < alpha = a < beta = b < RC = rc < # <
  pl = p``). This is also what api.osv.dev matches Packagist ranges with.
* NuGet — https://learn.microsoft.com/nuget/concepts/package-versioning
  ("Where NuGetVersion diverges from Semantic Versioning"): a 4th ``Revision``
  segment, only ``Major`` required, case-insensitive pre-release comparison,
  build metadata stripped, leading zeros removed.
* RubyGems — ``Gem::Version``: ``-`` becomes ``.pre.``, segments are runs of
  digits or letters, trailing zeros are dropped from the numeric run and from
  the prerelease run independently, and a string segment sorts BELOW a numeric
  one. Cross-checked against a real ``Gem::Version`` in
  ``test_rubygems_matches_a_live_gem_version_oracle``.

Every ordering case is asserted in BOTH directions and around the boundary, so
removing a false negative cannot quietly buy a false positive.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap

import pytest

from agent_bom.version_utils import compare_version_order, version_in_range

# ---------------------------------------------------------------------------
# Packagist / Composer — PHP version_compare
# ---------------------------------------------------------------------------

PACKAGIST_ECOSYSTEMS = ("packagist", "composer", "Packagist", "COMPOSER")

# (lower, higher) — strictly ascending pairs per PHP's documented part order.
PHP_ASCENDING_PAIRS = [
    ("2.4.5-p1", "2.4.5-p2"),
    ("2.4.5-p1", "2.4.5-p10"),
    ("2.4.5", "2.4.5-p1"),  # '#' < 'pl' = 'p'
    ("2.4.5-rc1", "2.4.5"),  # 'rc' < '#'
    ("1.0.0-dev", "1.0.0-alpha"),
    ("1.0.0-alpha", "1.0.0-beta"),
    ("1.0.0-beta", "1.0.0-RC1"),
    ("1.0.0-a", "1.0.0-b"),
    ("2.4.0rc1", "2.4.0"),  # dots inserted around non-numerics
    ("1.0.0-stable", "1.0.0"),  # unrecognised string sorts below every part
    ("2.4.4-p9", "2.4.4-p10"),  # numeric, not lexicographic
    ("2.4.5-p12", "2.4.6"),
    ("0.7.17a", "0.7.17b"),
]


@pytest.mark.parametrize("ecosystem", PACKAGIST_ECOSYSTEMS)
@pytest.mark.parametrize(("lower", "higher"), PHP_ASCENDING_PAIRS)
def test_packagist_orders_php_version_parts(ecosystem: str, lower: str, higher: str) -> None:
    assert compare_version_order(lower, higher, ecosystem) == -1
    assert compare_version_order(higher, lower, ecosystem) == 1
    assert compare_version_order(lower, lower, ecosystem) == 0
    assert compare_version_order(higher, higher, ecosystem) == 0


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("2.4.5-p1", "2.4.5.p1"),  # '-' and '.' canonicalise identically
        ("2.4.5_p1", "2.4.5-p1"),
        ("v2.4.5-p1", "2.4.5-p1"),
        ("1.0.0-pl1", "1.0.0-p1"),  # 'pl' = 'p'
        ("1.0.0-RC1", "1.0.0-rc1"),
    ],
)
def test_packagist_treats_equivalent_spellings_as_equal(left: str, right: str) -> None:
    assert compare_version_order(left, right, "packagist") == 0


def test_packagist_patch_window_matches_the_version_inside_it() -> None:
    """The measured false negative: [2.4.5-p1, 2.4.5-p2) must contain 2.4.5-p1."""
    assert version_in_range("2.4.5-p1", "2.4.5-p1", "2.4.5-p2", None, "packagist") is True
    assert version_in_range("2.4.5-p1", "2.4.5-p1", "2.4.5-p2", None, "composer") is True


def test_packagist_patch_window_excludes_versions_outside_it() -> None:
    """The other direction: the fix must not turn the window into a catch-all."""
    # At the exclusive upper bound, and above it.
    assert version_in_range("2.4.5-p2", "2.4.5-p1", "2.4.5-p2", None, "packagist") is False
    assert version_in_range("2.4.5-p3", "2.4.5-p1", "2.4.5-p2", None, "packagist") is False
    assert version_in_range("2.4.6", "2.4.5-p1", "2.4.5-p2", None, "packagist") is False
    # Below the inclusive lower bound.
    assert version_in_range("2.4.5", "2.4.5-p1", "2.4.5-p2", None, "packagist") is False
    assert version_in_range("2.4.4-p9", "2.4.5-p1", "2.4.5-p2", None, "packagist") is False
    # last_affected is inclusive; one patch level past it is not affected.
    assert version_in_range("2.4.5-p2", "2.4.5-p1", None, "2.4.5-p2", "packagist") is True
    assert version_in_range("2.4.5-p3", "2.4.5-p1", None, "2.4.5-p2", "packagist") is False


# ---------------------------------------------------------------------------
# NuGet — NuGetVersion (SemVer 2.0 + Revision, case-insensitive prerelease)
# ---------------------------------------------------------------------------

NUGET_ASCENDING_PAIRS = [
    ("2.4.5-p1", "2.4.5-p2"),
    ("1.0.0-alpha", "1.0.0"),
    ("1.0.1-aaa", "1.0.1-alpha10"),  # docs' SemVer 2.0 sorting sample, reversed
    ("1.0.1-alpha10", "1.0.1-alpha2"),
    ("1.0.1-alpha2", "1.0.1-beta"),
    ("1.0.1-beta", "1.0.1-open"),
    ("1.0.1-rc.2", "1.0.1-rc.10"),  # dotted numeric identifiers compare numerically
    ("1.0.1-open", "1.0.1-rc.2"),
    ("1.0.1-zzz", "1.0.1"),
    ("1.0.0", "1.0.0.1"),  # the 4th Revision segment is significant
    ("1.0.0.1", "1.0.0.2"),
    ("1.0.0.9", "1.0.0.10"),
    ("1.0.0", "1.0.1"),
    ("1.0.0-rc1", "1.0.0-rc1-11259"),
    ("4.8.0-beta00005", "4.8.0-beta00017"),
]


@pytest.mark.parametrize(("lower", "higher"), NUGET_ASCENDING_PAIRS)
def test_nuget_orders_versions(lower: str, higher: str) -> None:
    assert compare_version_order(lower, higher, "nuget") == -1
    assert compare_version_order(higher, lower, "nuget") == 1
    assert compare_version_order(lower, lower, "nuget") == 0


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1.0.0.0", "1.0.0"),  # a zero Revision is omitted by normalization
        ("1", "1.0.0"),  # only Major is required
        ("1.0", "1.0.0.0"),
        ("1.00", "1.0"),  # leading zeros are removed
        ("1.01.1", "1.1.1"),
        ("1.00.0.1", "1.0.0.1"),
        ("1.0.7+r3456", "1.0.7"),  # build metadata is removed
        ("1.0.0-Alpha", "1.0.0-alpha"),  # prerelease compares case-insensitively
        ("1.0.0-RC.1", "1.0.0-rc.1"),
        ("v1.2.3", "1.2.3"),
    ],
)
def test_nuget_treats_normalized_forms_as_equal(left: str, right: str) -> None:
    assert compare_version_order(left, right, "nuget") == 0
    assert compare_version_order(right, left, "nuget") == 0


def test_nuget_revision_outranks_a_prerelease_label_on_the_same_base() -> None:
    """Revision is compared before the release label, per VersionComparer."""
    assert compare_version_order("1.0.0.1-alpha", "1.0.0", "nuget") == 1
    assert compare_version_order("1.0.0", "1.0.0.1-alpha", "nuget") == -1


def test_nuget_prerelease_window_matches_inside_and_excludes_the_bound() -> None:
    assert version_in_range("2.4.5-p1", "2.4.5-p1", "2.4.5-p2", None, "nuget") is True
    assert version_in_range("2.4.5-p2", "2.4.5-p1", "2.4.5-p2", None, "nuget") is False
    assert version_in_range("2.4.5", "2.4.5-p1", "2.4.5-p2", None, "nuget") is False
    assert version_in_range("1.0.0.1", "1.0.0", "1.0.0.2", None, "nuget") is True
    assert version_in_range("1.0.0.2", "1.0.0", "1.0.0.2", None, "nuget") is False


def test_nuget_is_not_routed_through_strict_semver() -> None:
    """Semver alone gets NuGet wrong; these are the cases that prove it."""
    # Strict SemVer cannot parse a 4th segment, and is case-SENSITIVE.
    assert compare_version_order("1.0.0.5", "1.0.0.4", "nuget") == 1
    assert compare_version_order("1.0.0-Beta", "1.0.0-beta", "nuget") == 0
    # ...but npm, which really is strict SemVer, keeps case-sensitive ordering.
    assert compare_version_order("1.0.0-Beta", "1.0.0-beta", "npm") == -1


# ---------------------------------------------------------------------------
# RubyGems — Gem::Version
# ---------------------------------------------------------------------------

GEM_ASCENDING_PAIRS = [
    ("5.0.0.beta1", "5.0.0.beta1.1"),
    ("5.0.0.beta1", "5.0.0.beta2"),
    ("5.0.0.beta1", "5.0.0"),
    ("1.0.0.rc1", "1.0.0.rc2"),
    ("1.0.0.pre.rc1", "1.0.0.rc1"),
    ("2.1.0pre1", "2.1.0"),
    ("1.4.0.beta.1", "1.4.0-beta.1"),  # '-' expands to '.pre.', which sorts above 'beta'
    ("1.4.0-beta.1", "1.4.0"),
    ("1.0.0.rc1.1", "1.0.0.rc2.0"),
    ("0.4.rc3", "0.4"),
    ("1.6.1.a", "1.6.1"),
    ("3.0.0.pre1", "3.0.0.pre12"),
    ("4.0.0.beta7", "4.0.0.beta.51"),
    ("1.0.0", "1.0.0.1"),
    ("1.2.3", "1.2.4"),
]


@pytest.mark.parametrize(("lower", "higher"), GEM_ASCENDING_PAIRS)
def test_rubygems_orders_versions(lower: str, higher: str) -> None:
    assert compare_version_order(lower, higher, "rubygems") == -1
    assert compare_version_order(higher, lower, "rubygems") == 1
    assert compare_version_order(lower, lower, "rubygems") == 0


@pytest.mark.parametrize(("left", "right"), [("1.0", "1.0.0"), ("1.0.0", "1.0.0.0"), ("2.0", "2.0.0.0")])
def test_rubygems_drops_trailing_zero_segments(left: str, right: str) -> None:
    assert compare_version_order(left, right, "rubygems") == 0
    assert compare_version_order(right, left, "rubygems") == 0


def test_rubygems_prerelease_window_matches_inside_and_excludes_the_bound() -> None:
    assert version_in_range("5.0.0.beta1", "5.0.0.beta1", "5.0.0.beta1.1", None, "rubygems") is True
    assert version_in_range("5.0.0.beta1.1", "5.0.0.beta1", "5.0.0.beta1.1", None, "rubygems") is False
    assert version_in_range("5.0.0", "5.0.0.beta1", "5.0.0.beta1.1", None, "rubygems") is False
    assert version_in_range("4.9.9", "5.0.0.beta1", "5.0.0.beta1.1", None, "rubygems") is False


def test_rubygems_rejects_strings_gem_version_would_reject() -> None:
    """Fail closed rather than guess: a non-Gem string stays uncomparable."""
    assert compare_version_order("not-a-version!", "1.0.0", "rubygems") is None
    assert compare_version_order("1.0.0", "1.0.0+build", "rubygems") is None


# --- oracle -----------------------------------------------------------------

_GEM_ORACLE_SCRIPT = textwrap.dedent(
    """
    require 'rubygems'
    require 'json'
    pairs = JSON.parse(STDIN.read)
    puts JSON.dump(pairs.map { |a, b| Gem::Version.new(a) <=> Gem::Version.new(b) })
    """
)


def test_rubygems_matches_a_live_gem_version_oracle() -> None:
    """Cross-check the comparator against a real ``Gem::Version``.

    Skipped when no ruby is installed; the hard-coded tables above still pin the
    behaviour in that case, so this never becomes the only guard.
    """
    ruby = shutil.which("ruby")
    if ruby is None:  # pragma: no cover - environment dependent
        pytest.skip("ruby not installed")

    pairs = [list(pair) for pair in GEM_ASCENDING_PAIRS]
    pairs += [[b, a] for a, b in GEM_ASCENDING_PAIRS]
    pairs += [["1.0", "1.0.0"], ["1.0.0", "1.0.0.0"], ["5.0.0.beta1", "5.0.0.beta1"]]

    proc = subprocess.run(  # noqa: S603
        [ruby, "-e", _GEM_ORACLE_SCRIPT],
        input=json.dumps(pairs),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:  # pragma: no cover - environment dependent
        pytest.skip(f"ruby oracle unavailable: {proc.stderr.strip()}")

    expected = json.loads(proc.stdout)
    assert len(expected) == len(pairs)
    mismatches = [
        (left, right, want, compare_version_order(left, right, "rubygems"))
        for (left, right), want in zip(pairs, expected)
        if compare_version_order(left, right, "rubygems") != want
    ]
    assert not mismatches, f"Gem::Version disagreements: {mismatches}"
