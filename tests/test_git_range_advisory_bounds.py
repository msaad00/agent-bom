"""GIT-typed advisory bounds must never be guessed at, and never dropped in silence.

OSV advisories can bound a vulnerable window by git commit
(``{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "<sha>"}]}``).
A SHA carries no order relative to a release version — establishing membership
would need the repository's commit graph, which the scanner does not have. So
the matcher fails closed, which is right.

What was wrong is that it did so invisibly, and via the wrong mechanism:

* ``_is_version_affected`` accepted ``GIT`` alongside ``SEMVER``/``ECOSYSTEM``
  and pushed SHA bounds into the version comparator, relying on
  ``version_in_range``'s SHA guard to bail out further down — one layer away
  from the decision;
* an advisory whose ONLY range for our package is GIT evaluated to "not
  affected" for every version, with nothing in ``scan_warnings`` and no
  confidence signal, so a real recall gap looked identical to a clean result.

Bounds pinned to live OSV on 2026-08-01 (``PYSEC-2022-42980`` /
``GHSA-q4mp-jvh2-76fj`` / CVE-2022-45199).
"""

from __future__ import annotations

import pytest

from agent_bom.models import Package
from agent_bom.scanners.package_scan import _is_version_affected, build_vulnerabilities
from agent_bom.scanners.state import consume_scan_warnings, reset_scan_warnings

_PILLOW_FIX_SHA = "2444cddab2f83f28687c7c20871574acbb6dbcf3"


@pytest.fixture(autouse=True)
def _clean_warnings():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def _pypi_pillow(version: str) -> Package:
    return Package(name="pillow", version=version, ecosystem="pypi", purl=f"pkg:pypi/pillow@{version}")


def _git_only_advisory() -> dict:
    """An advisory whose only bound for our package is a commit SHA."""
    return {
        "id": "OSV-2022-GIT-ONLY",
        "summary": "Heap overflow reachable from ImageFile",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/python-pillow/Pillow",
                        "events": [{"introduced": "0"}, {"fixed": _PILLOW_FIX_SHA}],
                    }
                ],
            }
        ],
    }


def _git_plus_ecosystem_advisory() -> dict:
    """PYSEC-2022-42980's real shape: a GIT range beside an ECOSYSTEM range.

    ``versions`` is dropped here so the range path is what gets exercised; the
    live entry also enumerates ``versions`` and that path is covered separately.
    """
    return {
        "id": "PYSEC-2022-42980",
        "summary": "Pillow DoS via SAMPLESPERPIXEL",
        "aliases": ["CVE-2022-45199", "GHSA-q4mp-jvh2-76fj"],
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/python-pillow/Pillow",
                        "events": [{"introduced": "0"}, {"fixed": _PILLOW_FIX_SHA}],
                    },
                    {"type": "ECOSYSTEM", "events": [{"introduced": "9.2.0"}, {"fixed": "9.3.0"}]},
                ],
            }
        ],
    }


# ── the ECOSYSTEM range decides when one exists alongside GIT ────────────────


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("9.0.0", False),  # below the ECOSYSTEM `introduced` — genuinely not affected
        ("9.1.0", False),
        ("9.2.0", True),  # the one release GitHub scopes CVE-2022-45199 to
        ("9.3.0", False),  # fixed
    ],
)
def test_ecosystem_range_decides_when_git_range_sits_beside_it(version: str, affected: bool) -> None:
    assert _is_version_affected(_git_plus_ecosystem_advisory(), "pillow", version, "pypi") is affected


def test_git_range_beside_ecosystem_range_records_no_warning() -> None:
    """The GIT bound cost nothing here — the ECOSYSTEM range answered."""
    _is_version_affected(_git_plus_ecosystem_advisory(), "pillow", "9.2.0", "pypi")
    assert not consume_scan_warnings()


# ── a GIT-only advisory is a visible gap, not a silent "clean" ───────────────


@pytest.mark.parametrize("version", ["1.0.0", "9.0.0", "999.0.0"])
def test_git_only_advisory_never_claims_a_match(version: str) -> None:
    """SHA ordering is unknowable without the repo — do not guess it."""
    assert _is_version_affected(_git_only_advisory(), "pillow", version, "pypi") is False


def test_git_only_advisory_records_a_scan_warning() -> None:
    _is_version_affected(_git_only_advisory(), "pillow", "9.0.0", "pypi")
    warnings = consume_scan_warnings()
    assert warnings, "a GIT-only advisory bound is a recall gap and must be visible"
    joined = " ".join(warnings)
    assert "OSV-2022-GIT-ONLY" in joined
    assert "pillow" in joined
    assert "commit" in joined.lower() or "git" in joined.lower()


def test_git_only_warning_is_not_emitted_for_ordinary_advisories() -> None:
    """Non-vacuous: an ECOSYSTEM-only advisory produces no warning."""
    advisory = {
        "id": "CVE-2026-0001",
        "summary": "ordinary",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.3.0"}]}],
            }
        ],
    }
    assert _is_version_affected(advisory, "pillow", "9.0.0", "pypi") is True
    assert not consume_scan_warnings()


def test_git_only_advisory_is_dropped_from_findings_but_warned_about() -> None:
    """End to end through build_vulnerabilities, not just the predicate."""
    vulns = build_vulnerabilities([_git_only_advisory()], _pypi_pillow("9.0.0"))
    assert [v.id for v in vulns] == []
    assert any("OSV-2022-GIT-ONLY" in w for w in consume_scan_warnings())


# ── an explicit versions list still wins, and GIT bounds never reach the
#    version comparator ───────────────────────────────────────────────────────


def test_explicit_versions_list_still_takes_precedence() -> None:
    advisory = _git_only_advisory()
    advisory["affected"][0]["versions"] = ["9.0.0", "9.1.0"]
    assert _is_version_affected(advisory, "pillow", "9.0.0", "pypi") is True
    assert _is_version_affected(advisory, "pillow", "9.2.0", "pypi") is False


# ── the same class on the DB sync side ──────────────────────────────────────


def test_db_sync_does_not_store_commit_bounded_windows() -> None:
    """A SHA in the ``introduced``/``fixed`` columns is a bound nothing can use."""
    from agent_bom.db.sync import _parse_osv_entry

    parsed = _parse_osv_entry(_git_plus_ecosystem_advisory())
    assert parsed is not None
    _vuln_row, affected_rows = parsed
    bounds = [(row["introduced"], row["fixed"], row["last_affected"]) for row in affected_rows]
    assert bounds == [("9.2.0", "9.3.0", "")], f"commit-bounded window stored: {bounds}"


def test_db_sync_never_recommends_a_commit_sha_as_the_fix() -> None:
    """``fixed_version`` is rendered to users as "upgrade to X"."""
    from agent_bom.db.sync import _parse_osv_entry

    parsed = _parse_osv_entry(_git_only_advisory())
    assert parsed is not None
    vuln_row, affected_rows = parsed
    assert vuln_row["fixed_version"] != _PILLOW_FIX_SHA
    assert not vuln_row["fixed_version"], "a commit SHA is not an upgrade target"
    assert affected_rows == [], "a commit-bounded window contributes no usable row"


def test_db_sync_keeps_a_decidable_commit_range() -> None:
    """``introduced: "0"`` needs no SHA ordering — keep it, as the matcher does."""
    from agent_bom.db.sync import _parse_osv_entry

    advisory = {
        "id": "OSV-2022-GIT-UNFIXED",
        "summary": "vulnerable from the first commit, unfixed",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [{"type": "GIT", "repo": "https://example.invalid", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    parsed = _parse_osv_entry(advisory)
    assert parsed is not None
    assert [(r["introduced"], r["fixed"]) for r in parsed[1]] == [("0", "")]


def test_commit_range_bounded_only_from_zero_is_still_decidable() -> None:
    """``introduced: "0"`` with no fix is OSV's "vulnerable from the first
    commit, unfixed" — no SHA ordering is needed to answer that, so dropping it
    would be a self-inflicted false negative."""
    advisory = {
        "id": "OSV-2022-GIT-UNFIXED",
        "summary": "OSS-Fuzz issue with no release-version bound",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/python-pillow/Pillow",
                        "events": [{"introduced": "0"}],
                    }
                ],
            }
        ],
    }
    assert _is_version_affected(advisory, "pillow", "999.0.0", "pypi") is True
    assert not consume_scan_warnings(), "nothing was unresolvable, so nothing to warn about"


def test_commit_introduced_bound_is_unresolvable_and_warned() -> None:
    """A SHA lower bound with no upper bound cannot place any version."""
    advisory = {
        "id": "OSV-2022-GIT-INTRODUCED-SHA",
        "summary": "introduced at a commit, unfixed",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/python-pillow/Pillow",
                        "events": [{"introduced": _PILLOW_FIX_SHA}],
                    }
                ],
            }
        ],
    }
    assert _is_version_affected(advisory, "pillow", "999.0.0", "pypi") is False
    assert any("OSV-2022-GIT-INTRODUCED-SHA" in w for w in consume_scan_warnings())


def test_db_sync_keeps_ordinary_ecosystem_windows() -> None:
    """Non-vacuous: the ECOSYSTEM path is untouched."""
    from agent_bom.db.sync import _parse_osv_entry

    advisory = {
        "id": "CVE-2026-0001",
        "summary": "ordinary",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.3.0"}]}],
            }
        ],
    }
    parsed = _parse_osv_entry(advisory)
    assert parsed is not None
    vuln_row, affected_rows = parsed
    assert vuln_row["fixed_version"] == "9.3.0"
    assert [(r["introduced"], r["fixed"]) for r in affected_rows] == [("0", "9.3.0")]


def test_git_bounds_are_not_offered_to_the_version_comparator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Structural guard: nothing may ask 'is 9.0.0 before <sha>?'."""
    import agent_bom.scanners.package_scan as package_scan

    seen: list[tuple[str | None, str | None, str | None]] = []
    real = package_scan._version_in_window

    def _spy(version, window, ecosystem):  # type: ignore[no-untyped-def]
        seen.append(window)
        return real(version, window, ecosystem)

    monkeypatch.setattr(package_scan, "_version_in_window", _spy)
    package_scan._is_version_affected(_git_plus_ecosystem_advisory(), "pillow", "9.2.0", "pypi")
    flat = [bound for window in seen for bound in window if bound]
    assert _PILLOW_FIX_SHA not in flat, "a commit SHA was passed to the version comparator"
