"""Regression tests for OSV fixed_version accuracy (issue #3642).

Covers three defects, all exercised with mocked OSV payloads (no live calls):

1. fixed_version dropped / nondeterministic — the enrich gate only re-fetched
   records missing a ``summary``; a record that had a summary but no
   ``affected`` block was left un-enriched so ``parse_fixed_version`` never saw
   the fix.
2. Cross-ecosystem bleed — a shared advisory listing affected entries for
   several ecosystems (jQuery/npm 3.4.0 alongside Django/PyPI 2.2.2) returned
   the wrong ecosystem's fix.
3. False negative — a version enumerated in ``affected[].versions`` in a
   trailing-zero form (``django==2.2.0`` vs enumerated ``2.2``) was filtered
   out as "not affected".
"""

from __future__ import annotations

from typing import Any

import pytest
from rich.console import Console

from agent_bom.models import Package
from agent_bom.scanners import _is_version_affected, build_vulnerabilities, parse_fixed_version
from agent_bom.scanners.osv import (
    ecosystem_matches,
    enrich_results_if_needed,
    vuln_needs_enrichment,
)

# --- Defect 2: cross-ecosystem bleed --------------------------------------


def _shared_advisory() -> dict:
    """CVE-2019-11358 shape: jQuery (npm/NuGet/Maven) + Django (PyPI) in one record."""
    return {
        "id": "GHSA-6c3j-c64m-qhgq",
        "aliases": ["CVE-2019-11358"],
        "summary": "Prototype pollution",
        "affected": [
            {
                "package": {"name": "jquery", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.4.0"}]}],
            },
            {
                "package": {"name": "jQuery", "ecosystem": "NuGet"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.4.0"}]}],
            },
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0a1"}, {"fixed": "2.1.9"}]}],
            },
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.2a1"}, {"fixed": "2.2.2"}]}],
            },
        ],
    }


def test_no_cross_ecosystem_fix_bleed():
    """Django must get its PyPI fix (2.2.2), never jQuery's npm 3.4.0."""
    fixed = parse_fixed_version(_shared_advisory(), "django", "PyPI", current_version="2.2.0")
    assert fixed == "2.2.2"


def test_same_name_cross_ecosystem_does_not_bleed():
    """A same-name package in another ecosystem must not donate its fix."""
    vuln = {
        "id": "SHARED-1",
        "affected": [
            {
                "package": {"name": "foo", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
            },
            {
                "package": {"name": "foo", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            },
        ],
    }
    assert parse_fixed_version(vuln, "foo", "PyPI", current_version="1.0.0") == "1.2.3"


def test_ecosystem_matches_maps_internal_codes():
    """Internal ecosystem codes must map to their OSV names."""
    assert ecosystem_matches("Debian:11", "deb")
    assert ecosystem_matches("PyPI", "pypi")
    assert ecosystem_matches("Linux", "rpm")
    assert not ecosystem_matches("npm", "PyPI")
    # Unknown on either side -> nothing to disqualify on.
    assert ecosystem_matches("", "PyPI")
    assert ecosystem_matches("npm", "")


def test_build_vulnerabilities_reports_django_fix_not_jquery(monkeypatch):
    """End-to-end (build): CVE-2019-11358 on Django resolves to 2.2.2."""
    pkg = Package(name="django", version="2.2", ecosystem="PyPI")
    vulns = build_vulnerabilities([_shared_advisory()], pkg)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2019-11358"
    assert vulns[0].fixed_version == "2.2.2"


# --- Defect 3: versions-list trailing-zero false negative ------------------


def _pysec_2024_225() -> dict:
    """cryptography advisory: 2.3 enumerated in `versions` but outside the range."""
    return {
        "id": "PYSEC-2024-225",
        "aliases": ["CVE-2024-26130", "GHSA-6vqw-3v5j-54x4"],
        "summary": "NULL pointer dereference",
        "affected": [
            {
                "package": {"name": "cryptography", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "38.0.0"}, {"fixed": "42.0.4"}]},
                ],
                "versions": ["2.3", "38.0.0", "41.0.0"],
            }
        ],
    }


def test_version_in_explicit_list_is_affected():
    """cryptography 2.3 is enumerated in `versions` -> affected (CVE-2024-26130)."""
    assert _is_version_affected(_pysec_2024_225(), "cryptography", "2.3", "PyPI") is True


def test_trailing_zero_version_matches_enumerated_version():
    """django==2.2.0 must match an enumerated '2.2' (PEP 440 trailing-zero)."""
    vuln = {
        "id": "GHSA-x",
        "affected": [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.2a1"}, {"fixed": "2.2.2"}]}],
                "versions": ["2.2", "2.2.1"],
            },
        ],
    }
    assert _is_version_affected(vuln, "django", "2.2.0", "PyPI") is True


def test_version_not_enumerated_is_not_affected():
    """A version outside both the enumerated list and range is not affected."""
    vuln = {
        "id": "GHSA-y",
        "affected": [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.2a1"}, {"fixed": "2.2.2"}]}],
                "versions": ["2.2", "2.2.1"],
            },
        ],
    }
    assert _is_version_affected(vuln, "django", "2.2.5", "PyPI") is False


def test_cross_ecosystem_versions_do_not_flag_our_package():
    """Another ecosystem's enumerated versions must not mark our package affected."""
    vuln = {
        "id": "GHSA-z",
        "affected": [
            {"package": {"name": "foo", "ecosystem": "npm"}, "versions": ["1.0.0"]},
        ],
    }
    # foo/PyPI is not listed at all -> no same-ecosystem affected entry found ->
    # conservative True (trust OSV's original match); the npm versions list must
    # not be what decides it.
    assert _is_version_affected(vuln, "foo", "1.0.0", "PyPI") is True
    # And a different version still must not be filtered on the npm list.
    assert _is_version_affected(vuln, "foo", "2.0.0", "PyPI") is True


# --- Defect 1: enrich gate + determinism -----------------------------------


def test_vuln_needs_enrichment_gate():
    # Minimal batch stub -> needs enrichment.
    assert vuln_needs_enrichment({"id": "X", "modified": "t"}) is True
    # Has summary but NO affected -> STILL needs enrichment (the bug).
    assert vuln_needs_enrichment({"id": "X", "summary": "s"}) is True
    # Affected present but no ranges/versions -> needs enrichment.
    assert vuln_needs_enrichment({"id": "X", "affected": [{"package": {"name": "p"}}]}) is True
    # Fully resolvable (affected + ranges) -> no enrichment (deterministic, no refetch).
    assert vuln_needs_enrichment({"id": "X", "affected": [{"package": {"name": "p"}, "ranges": [{"events": []}]}]}) is False
    # summary-less record that already has affected/versions -> no refetch either.
    assert vuln_needs_enrichment({"id": "PYSEC-1", "affected": [{"package": {"name": "p"}, "versions": ["1.0"]}]}) is False
    # No id -> can't enrich.
    assert vuln_needs_enrichment({"summary": "s"}) is False


class _FakeResponse:
    def __init__(self, payload: dict):
        self.status_code = 200
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


@pytest.mark.asyncio
async def test_enrich_fetches_records_missing_affected_even_with_summary():
    """A record with a summary but no `affected` must be enriched (defect 1)."""
    detail = {
        "id": "PYSEC-2024-225",
        "summary": "NULL pointer dereference",
        "affected": [
            {
                "package": {"name": "cryptography", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "38.0.0"}, {"fixed": "42.0.4"}]}],
                "versions": ["2.3"],
            },
        ],
    }
    fetched: list[str] = []

    async def _fake_request(client, method, url, **kwargs):
        vid = url.rsplit("/", 1)[-1]
        fetched.append(vid)
        return _FakeResponse(detail)

    results = {
        "pypi:cryptography@2.3": [
            # HAS a summary, but NO affected -> old gate skipped it, dropping the fix.
            {"id": "PYSEC-2024-225", "summary": "NULL pointer dereference"},
        ]
    }
    out = await enrich_results_if_needed(
        results,
        console=Console(quiet=True),
        record_scan_warning=lambda _m: None,
        create_client_fn=lambda **kw: _FakeClient(),
        request_with_retry_fn=_fake_request,
    )
    assert fetched == ["PYSEC-2024-225"]
    enriched = out["pypi:cryptography@2.3"][0]
    assert enriched.get("affected"), "record must gain affected data after enrichment"
    assert parse_fixed_version(enriched, "cryptography", "PyPI", current_version="2.3") == "42.0.4"


@pytest.mark.asyncio
async def test_enrich_skips_records_already_resolvable():
    """Records that already carry affected ranges are not re-fetched (determinism)."""
    called: list[str] = []

    async def _fake_request(client, method, url, **kwargs):
        called.append(url)
        return _FakeResponse({})

    results = {
        "pypi:django@2.2": [
            {
                "id": "GHSA-ok",
                "affected": [
                    {"package": {"name": "django", "ecosystem": "PyPI"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.2"}]}]}
                ],
            },
        ]
    }
    await enrich_results_if_needed(
        results,
        console=Console(quiet=True),
        record_scan_warning=lambda _m: None,
        create_client_fn=lambda **kw: _FakeClient(),
        request_with_retry_fn=_fake_request,
    )
    assert called == [], "records with resolvable affected data must not be re-fetched"
