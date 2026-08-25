"""A scan that could check nothing must not report ``clean``.

With no usable local advisory DB and OSV erroring, nothing was consulted — yet
``check`` returned ``verdict: clean`` / exit 0 for a package with known CVEs.
``check --help`` already documents exit 2 as "Incomplete — insufficient context
for a trustworthy clean verdict", and the ``--offline`` path already behaves
that way; this is the same situation over the network.

The trap is that this must stay narrow: it fires only when the local DB has NO
advisories for the package's ecosystem AND the remote lookup failed. A DB that
covers the ecosystem answers the question on its own, and a successful remote
lookup that finds nothing is a genuine clean.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.scanners import state as scanner_state

PACKAGE = "jinja2@3.1.2"


@pytest.fixture(autouse=True)
def _clean_state():
    scanner_state.reset_scan_warnings()
    yield
    scanner_state.reset_scan_warnings()


def _run(monkeypatch, *, db_ecosystems: set[str], osv_failed: bool, args: list[str] | None = None):
    """Run `check` with the local DB and the OSV outcome both under control."""
    import agent_bom.scanners as scanners_mod

    # package_scan resolves these through ``agent_bom.scanners`` so tests can
    # replace them; patch them where the runtime actually looks them up.
    monkeypatch.setattr(scanners_mod, "_db_covered_ecosystems", lambda *_args: db_ecosystems, raising=False)
    monkeypatch.setattr(scanners_mod, "_scan_packages_local_db", lambda packages: (0, set()), raising=False)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)

    async def _query_osv_batch(packages, *_args, **_kwargs):
        if osv_failed:
            scanner_state.record_scan_warning(f"{len(packages)} package lookup error(s)")
            scanner_state.record_coverage_warning(
                {
                    "kind": "remote_lookup_error",
                    "release": "remote:osv",
                    "ecosystems": sorted({pkg.ecosystem.lower() for pkg in packages}),
                    "package_count": len(packages),
                }
            )
        return {}

    monkeypatch.setattr(scanners_mod, "query_osv_batch", _query_osv_batch, raising=False)
    return CliRunner().invoke(main, ["check", PACKAGE, "-e", "pypi", *(args or [])])


def test_empty_db_plus_remote_failure_is_incomplete(monkeypatch) -> None:
    result = _run(monkeypatch, db_ecosystems=set(), osv_failed=True)
    assert result.exit_code == 2, result.output
    assert "incomplete" in result.output.lower()


def test_the_incomplete_verdict_reaches_the_json_payload(monkeypatch, tmp_path) -> None:
    import json

    out = tmp_path / "check.json"
    result = _run(monkeypatch, db_ecosystems=set(), osv_failed=True, args=["--format", "json", "-o", str(out)])
    assert result.exit_code == 2, result.output
    payload = json.loads(out.read_text())
    assert payload["verdict"] == "incomplete"
    assert payload["exit_code"] == 2
    assert payload["scan_warnings"], "the upstream failure left no machine-readable trace"


def test_a_successful_remote_lookup_with_no_findings_is_still_clean(monkeypatch) -> None:
    """Non-vacuous: don't turn every empty-DB scan into an incomplete."""
    result = _run(monkeypatch, db_ecosystems=set(), osv_failed=False)
    assert result.exit_code == 0, result.output
    assert "no known vulnerabilities" in result.output.lower()


def test_a_db_that_covers_the_ecosystem_is_still_clean(monkeypatch) -> None:
    """The DB answered the question; a flaky remote does not invalidate it."""
    result = _run(monkeypatch, db_ecosystems={"pypi"}, osv_failed=True)
    assert result.exit_code == 0, result.output
