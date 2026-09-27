"""npm caret/tilde ranges resolve to the correct semver bounds.

Regression guard for the 0.x caret bug: `^0.2.3` means `>=0.2.3 <0.3.0`, not
"any 0.x". Resolving it to the highest 0.x picked the wrong transitive version
and therefore matched the wrong CVEs.
"""

from __future__ import annotations

import pytest

from agent_bom.parsers.npm_semver import classify_npm_spec, max_satisfying, npm_exact_version, resolve_npm_spec
from agent_bom.transitive import _npm_caret_tilde_bounds, _resolve_npm_version, _semver_tuple


def _pkg(*versions: str) -> dict:
    return {"dist-tags": {"latest": versions[-1]}, "versions": {v: {} for v in versions}}


def test_caret_zero_major_pins_minor():
    # ^0.2.3 → >=0.2.3 <0.3.0 — must not jump to 0.9.0
    assert _resolve_npm_version("^0.2.3", _pkg("0.2.3", "0.2.9", "0.3.0", "0.9.0")) == "0.2.9"


def test_caret_zero_major_zero_minor_pins_patch():
    # ^0.0.3 → >=0.0.3 <0.0.4
    assert _resolve_npm_version("^0.0.3", _pkg("0.0.3", "0.0.4", "0.1.0")) == "0.0.3"


def test_caret_nonzero_major_pins_major():
    assert _resolve_npm_version("^1.2.3", _pkg("1.2.3", "1.9.0", "2.0.0")) == "1.9.0"


def test_tilde_pins_minor():
    assert _resolve_npm_version("~1.2.3", _pkg("1.2.3", "1.2.9", "1.3.0")) == "1.2.9"


def test_tilde_bare_major_pins_major():
    assert _resolve_npm_version("~1", _pkg("1.0.0", "1.5.0", "2.0.0")) == "1.5.0"


def test_prerelease_excluded_unless_only_match():
    # stable 1.2.4 preferred over prerelease 1.3.0-beta within ^1.2.3
    assert _resolve_npm_version("^1.2.3", _pkg("1.2.3", "1.2.4", "1.3.0-beta")) == "1.2.4"


def test_unsatisfiable_range_does_not_fall_back_to_latest():
    # Falling back to `latest` (2.0.0) for ^5.0.0 reported a version the range
    # excludes and matched that version's CVEs. Unsatisfiable → unresolved.
    assert _resolve_npm_version("^5.0.0", _pkg("1.0.0", "2.0.0")) == ""


def test_bounds_helper():
    assert _npm_caret_tilde_bounds("^0.2.3") == ((0, 2, 3), (0, 3, 0))
    assert _npm_caret_tilde_bounds("^1.2.3") == ((1, 2, 3), (2, 0, 0))
    assert _npm_caret_tilde_bounds("~1.2") == ((1, 2, 0), (1, 3, 0))
    assert _npm_caret_tilde_bounds(">=1.0.0") is None


def test_semver_tuple_pads_and_strips():
    assert _semver_tuple("1.2") == (1, 2, 0)
    assert _semver_tuple("1.2.3-beta.1") == (1, 2, 3)
    assert _semver_tuple("not-a-version") is None


# ── Full npm range grammar (node-semver) ─────────────────────────────────────

_FORM_DATA = ("3.0.1", "4.0.0", "4.0.1", "4.0.3", "4.0.4", "4.0.5", "4.0.6", "5.0.0-beta.1")
_MINIPASS = ("3.3.6", "5.0.0", "6.0.2", "7.0.4", "7.1.2")


@pytest.mark.parametrize(
    ("spec", "versions", "expected"),
    [
        ("^4.0.0", _FORM_DATA, "4.0.6"),
        ("5.0.0 || ^6.0.2 || ^7.0.0", _MINIPASS, "7.1.2"),
        ("^3.0.0 || ^5.0.0", _MINIPASS, "5.0.0"),
        ("*", _MINIPASS, "7.1.2"),
        ("x", _MINIPASS, "7.1.2"),
        ("", _MINIPASS, "7.1.2"),
        ("6.x", _MINIPASS, "6.0.2"),
        ("7.0.*", _MINIPASS, "7.0.4"),
        ("7", _MINIPASS, "7.1.2"),
        (">=5.0.0 <7.0.0", _MINIPASS, "6.0.2"),
        (">= 5.0.0 < 7", _MINIPASS, "6.0.2"),
        ("5.0.0 - 6", _MINIPASS, "6.0.2"),
        ("3.0.0 - 7.0", _MINIPASS, "7.0.4"),
        (">6", _MINIPASS, "7.1.2"),
        (">6.0", _MINIPASS, "7.1.2"),
        (">7", _MINIPASS, None),
        ("<=6.0", _MINIPASS, "6.0.2"),
        ("<6.0.2", _MINIPASS, "5.0.0"),
        ("~7.0.1", _MINIPASS, "7.0.4"),
        ("=6.0.2", _MINIPASS, "6.0.2"),
        ("v6.0.2", _MINIPASS, "6.0.2"),
        ("^9.0.0", _MINIPASS, None),
        (">=5.0.0-beta.0 <6", _FORM_DATA, "5.0.0-beta.1"),
        ("^5.0.0", _FORM_DATA, None),
        ("^0.0", ("0.0.1", "0.0.9", "0.1.0"), "0.0.9"),
        ("^0.2.3", ("0.2.3", "0.2.9", "0.3.0"), "0.2.9"),
        ("not a range!", _MINIPASS, None),
    ],
)
def test_max_satisfying_follows_node_semver(spec, versions, expected):
    assert max_satisfying(versions, spec) == expected


@pytest.mark.parametrize(
    ("spec", "kind"),
    [
        ("4.0.6", "exact"),
        ("=4.0.6", "exact"),
        ("v4.0.6", "exact"),
        ("1.0.0-rc.1", "exact"),
        ("^4.0.0", "range"),
        ("5.0.0 || ^6.0.2 || ^7.0.0", "range"),
        ("*", "range"),
        ("", "range"),
        ("1.x", "range"),
        ("1.2", "range"),
        ("latest", "tag"),
        ("next", "tag"),
        ("git+https://github.com/org/repo.git#v1.0.0", "non_registry"),
        ("github:org/repo", "non_registry"),
        ("org/repo", "non_registry"),
        ("file:../local", "non_registry"),
        ("https://example.com/pkg.tgz", "non_registry"),
        ("npm:other@^1.0.0", "non_registry"),
        ("workspace:*", "non_registry"),
        ("link:../x", "non_registry"),
    ],
)
def test_classify_npm_spec(spec, kind):
    assert classify_npm_spec(spec) == kind


def test_exact_version_normalizes_prefixes():
    assert npm_exact_version("=4.0.6") == "4.0.6"
    assert npm_exact_version("v4.0.6") == "4.0.6"
    assert npm_exact_version(" 4.0.6 ") == "4.0.6"
    assert npm_exact_version("^4.0.6") is None
    assert npm_exact_version("4.0") is None


def test_resolve_prefers_latest_tag_when_it_satisfies():
    # npm-pick-manifest: the defaultTag wins when it satisfies the range.
    packument = {"dist-tags": {"latest": "4.0.4"}, "versions": {v: {} for v in _FORM_DATA}}
    assert resolve_npm_spec("^4.0.0", packument) == "4.0.4"
    assert resolve_npm_spec("^3.0.0", packument) == "3.0.1"
    assert resolve_npm_spec("latest", packument) == "4.0.4"
    assert resolve_npm_spec("4.0.1", packument) == "4.0.1"
    assert resolve_npm_spec("beta", {"dist-tags": {"beta": "5.0.0-beta.1"}, "versions": {}}) == "5.0.0-beta.1"
    assert resolve_npm_spec("^9.0.0", packument) is None
    assert resolve_npm_spec("github:org/repo", packument) is None
    assert resolve_npm_spec("nosuchtag", packument) is None
    assert resolve_npm_spec("9.9.9", packument) is None
