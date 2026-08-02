"""A dropped advisory bound must leave a machine-readable trace.

``version_in_range`` fails CLOSED: a bound it cannot compare can never
establish a match, so the advisory is discarded. That policy is defensible —
discarding the EVIDENCE of it is not. The drop was only ever written to a
logger, so JSON/SARIF consumers, the exit code and the console all saw a result
indistinguishable from a genuinely clean one.

These tests pin that the drop reaches ``scan_warnings``, that it says WHICH
bound was dropped, and that it is reported on every scan rather than only the
first one in the process (the log side is memoised; the warning must not be).
"""

from __future__ import annotations

import pytest

from agent_bom.scanners.state import consume_scan_warnings, reset_scan_warnings
from agent_bom.version_utils import version_in_range

# A real shape from the local advisory DB: a distro-style version that leaked
# into a PyPI advisory bound. PEP 440 rejects it, it carries no strippable
# local/pre-release suffix, and it is not a commit SHA — so the comparator
# legitimately gives up and the bound is dropped.
UNCOMPARABLE = "0.8.3ubuntu7.5"


@pytest.fixture(autouse=True)
def _clean_warnings():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def test_uncomparable_fixed_bound_is_recorded_as_a_scan_warning() -> None:
    assert version_in_range("1.2.3", None, UNCOMPARABLE, None, "pypi") is False
    warnings = consume_scan_warnings()
    assert any(UNCOMPARABLE in warning for warning in warnings), warnings
    assert any("pypi" in warning for warning in warnings), warnings


def test_uncomparable_last_affected_bound_is_recorded() -> None:
    assert version_in_range("1.2.3", None, None, UNCOMPARABLE, "pypi") is False
    assert any(UNCOMPARABLE in warning for warning in consume_scan_warnings())


def test_uncomparable_introduced_bound_is_recorded() -> None:
    assert version_in_range("1.2.3", UNCOMPARABLE, None, None, "pypi") is False
    assert any(UNCOMPARABLE in warning for warning in consume_scan_warnings())


def test_the_warning_is_reported_again_on_a_later_scan() -> None:
    """The log is deduped per process; the warning channel must not be.

    Two `check` runs in one process share the module-level cache. If the
    recording rode on that cache, the second scan would silently drop the same
    bound with an empty ``scan_warnings``.
    """
    version_in_range("1.2.3", None, UNCOMPARABLE, None, "pypi")
    assert consume_scan_warnings(), "first scan recorded nothing"

    reset_scan_warnings()
    # A distinct version so the version_in_range LRU cache cannot serve it.
    version_in_range("1.2.4", None, UNCOMPARABLE, None, "pypi")
    assert consume_scan_warnings(), "second scan lost the dropped-bound warning"


def test_a_comparable_bound_records_nothing() -> None:
    """Non-vacuous: the channel stays silent when nothing was dropped."""
    assert version_in_range("1.2.3", "1.0.0", "2.0.0", None, "pypi") is True
    assert consume_scan_warnings() == []
