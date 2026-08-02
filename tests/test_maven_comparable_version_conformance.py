"""Maven ordering must match ``ComparableVersion``, not approximate it.

Maven version order is not SemVer and not PEP 440 — it is defined by the
algorithm in ``org.apache.maven.artifact.versioning.ComparableVersion`` and the
POM Reference "Version Order Specification"
(https://maven.apache.org/pom.html#version-order-specification).

The vectors below are Apache Maven's OWN conformance data, taken from
``maven-artifact``'s ``ComparableVersionTest``: ``VERSIONS_QUALIFIER`` and
``VERSIONS_NUMBER`` are asserted strictly ascending across every pair, and the
equality vectors come from ``testVersionsEqual``. Importing the upstream
vectors rather than inventing our own is the point: a hand-written table only
tests the ordering we already believed in.

A Maven ordering error is not cosmetic — the comparator decides whether an
advisory's ``introduced`` / ``fixed`` bound contains the installed artifact, so
getting it wrong is a false positive or a missed CVE.
"""

from __future__ import annotations

import itertools

import pytest

from agent_bom.version_utils import _compare_maven_versions, compare_version_order

# ComparableVersionTest.VERSIONS_QUALIFIER — strictly ascending.
VERSIONS_QUALIFIER = [
    "1-alpha2snapshot",
    "1-alpha2",
    "1-alpha-123",
    "1-beta-2",
    "1-beta123",
    "1-m2",
    "1-m11",
    "1-rc",
    "1-cr2",
    "1-rc123",
    "1-SNAPSHOT",
    "1",
    "1-sp",
    "1-sp2",
    "1-sp123",
    "1-abc",
    "1-def",
    "1-pom-1",
    "1-1-snapshot",
    "1-1",
    "1-2",
    "1-123",
]

# ComparableVersionTest.VERSIONS_NUMBER — strictly ascending.
VERSIONS_NUMBER = [
    "2.0",
    "2.0.a",
    "2-1",
    "2.0.2",
    "2.0.123",
    "2.1.0",
    "2.1-a",
    "2.1b",
    "2.1-c",
    "2.1-1",
    "2.1.0.1",
    "2.2",
    "2.123",
    "11.a2",
    "11.a11",
    "11.b2",
    "11.b11",
    "11.m2",
    "11.m11",
    "11",
    "11.a",
    "11b",
    "11c",
    "11m",
]

# ComparableVersionTest.testVersionsEqual
VERSIONS_EQUAL = [
    ("1", "1"),
    ("1", "1.0"),
    ("1", "1.0.0"),
    ("1.0", "1.0.0"),
    ("1", "1-0"),
    ("1", "1.0-0"),
    ("1.0", "1.0-0"),
    ("1a", "1-a"),
    ("1a", "1.0-a"),
    ("1a", "1.0.0-a"),
    ("1.0a", "1-a"),
    ("1.0.0a", "1-a"),
    ("1x", "1-x"),
    ("1x", "1.0-x"),
    ("1x", "1.0.0-x"),
    ("1.0x", "1-x"),
    ("1.0.0x", "1-x"),
    ("1ga", "1"),
    ("1release", "1"),
    ("1final", "1"),
    ("1cr", "1rc"),
    ("1a1", "1-alpha-1"),
    ("1b2", "1-beta-2"),
    ("1m3", "1-milestone-3"),
    ("1X", "1x"),
    ("1A", "1a"),
    ("1B", "1b"),
    ("1M", "1m"),
    ("1Ga", "1"),
    ("1GA", "1"),
    ("1RELEASE", "1"),
    ("1release", "1"),
    ("1RELeaSE", "1"),
    ("1Final", "1"),
    ("1FinaL", "1"),
    ("1FINAL", "1"),
    ("1Cr", "1Rc"),
    ("1cR", "1rC"),
    ("1m3", "1Milestone3"),
    ("1m3", "1MILESTONE3"),
    ("1-1.foo-bar1baz-.1", "1-1.foo-bar-1-baz-0.1"),
]


def _ascending_pairs(sequence: list[str]) -> list[tuple[str, str]]:
    return [(low, high) for low, high in itertools.combinations(sequence, 2)]


@pytest.mark.parametrize(("low", "high"), _ascending_pairs(VERSIONS_QUALIFIER))
def test_qualifier_order_matches_upstream(low: str, high: str) -> None:
    assert _compare_maven_versions(low, high) < 0, f"expected {low} < {high}"
    assert _compare_maven_versions(high, low) > 0, f"expected {high} > {low}"


@pytest.mark.parametrize(("low", "high"), _ascending_pairs(VERSIONS_NUMBER))
def test_number_order_matches_upstream(low: str, high: str) -> None:
    assert _compare_maven_versions(low, high) < 0, f"expected {low} < {high}"
    assert _compare_maven_versions(high, low) > 0, f"expected {high} > {low}"


@pytest.mark.parametrize(("left", "right"), VERSIONS_EQUAL)
def test_equal_versions_match_upstream(left: str, right: str) -> None:
    assert _compare_maven_versions(left, right) == 0, f"expected {left} == {right}"
    assert _compare_maven_versions(right, left) == 0, f"expected {right} == {left}"


@pytest.mark.parametrize("padding", range(1, 19))
def test_leading_zeroes_are_insignificant(padding: int) -> None:
    """``ComparableVersionTest.testVersionEqualWithLeadingZeroes``."""
    assert _compare_maven_versions("0" * padding + "1", "1") == 0
    assert _compare_maven_versions("0" * padding, "0") == 0


# ── the shapes real Maven advisories actually carry ─────────────────────────


@pytest.mark.parametrize(
    ("low", "high"),
    [
        ("5.0.4.RELEASE", "5.0.5.RELEASE"),
        ("4.3.6.RELEASE", "5.0.4.RELEASE"),
        ("5.2.4.Final", "5.2.5.Final"),
        ("4.1.59.Final", "4.1.60.Final"),
        ("2.1.0.RC1", "2.1.0.RELEASE"),  # a release outranks its own candidate
        ("5.0.0.M1", "5.0.0.RELEASE"),
        ("9.0.30", "9.0.31"),
        ("1.0.0-SNAPSHOT", "1.0.0"),
    ],
)
def test_real_artifact_qualifier_ordering(low: str, high: str) -> None:
    assert compare_version_order(low, high, "maven") == -1
    assert compare_version_order(high, low, "maven") == 1
