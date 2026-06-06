"""npm caret/tilde ranges resolve to the correct semver bounds.

Regression guard for the 0.x caret bug: `^0.2.3` means `>=0.2.3 <0.3.0`, not
"any 0.x". Resolving it to the highest 0.x picked the wrong transitive version
and therefore matched the wrong CVEs.
"""

from __future__ import annotations

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


def test_falls_back_to_latest_when_no_match():
    assert _resolve_npm_version("^5.0.0", _pkg("1.0.0", "2.0.0")) == "2.0.0"


def test_bounds_helper():
    assert _npm_caret_tilde_bounds("^0.2.3") == ((0, 2, 3), (0, 3, 0))
    assert _npm_caret_tilde_bounds("^1.2.3") == ((1, 2, 3), (2, 0, 0))
    assert _npm_caret_tilde_bounds("~1.2") == ((1, 2, 0), (1, 3, 0))
    assert _npm_caret_tilde_bounds(">=1.0.0") is None


def test_semver_tuple_pads_and_strips():
    assert _semver_tuple("1.2") == (1, 2, 0)
    assert _semver_tuple("1.2.3-beta.1") == (1, 2, 3)
    assert _semver_tuple("not-a-version") is None
