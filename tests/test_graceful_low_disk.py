"""Graceful degradation on a full disk (ENOSPC) — degrade, never crash.

Covers the three write sites that crashed a live low-disk run *after* the scan
had already computed its findings:

  1. enrichment KEV / NVD / EPSS cache writes  → warn once, continue
  2. the CLI update-check stamp write          → silently degrade to no-cache
  3. the ``-o`` report file write              → emit results to stdout / skip,
     never propagate a traceback (so the real exit code still runs)

Also verifies ``AGENT_BOM_STATE_DIR`` redirects cache writes off ``$HOME``.
"""

from __future__ import annotations

import errno
import json
from datetime import datetime
from pathlib import Path

import pytest

import agent_bom.cli._common as cli_common
import agent_bom.enrichment as enrichment
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._output import render_output
from agent_bom.models import AIBOMReport


def _enospc(*_args, **_kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


# ── enrichment cache writes (site 1) ──────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_enrichment(tmp_path, monkeypatch):
    monkeypatch.setattr(enrichment, "_ENRICHMENT_CACHE_DIR", tmp_path)
    monkeypatch.setattr(enrichment, "_KEV_CACHE_FILE", tmp_path / "kev_cache.json")
    monkeypatch.setattr(enrichment, "_nvd_file_cache", {"CVE-2025-1": {"_cached_at": 0}})
    monkeypatch.setattr(enrichment, "_epss_file_cache", {})
    monkeypatch.setattr(enrichment, "_enrichment_cache_loaded", True)
    monkeypatch.setattr(enrichment, "_low_disk_warned", False)


def test_enrichment_cache_enospc_warns_and_continues(monkeypatch, caplog):
    """A full disk on the NVD/EPSS cache write degrades to no-cache, never raises."""
    monkeypatch.setattr(enrichment.tempfile, "mkstemp", _enospc)
    with caplog.at_level("WARNING"):
        enrichment._save_enrichment_cache()  # must not raise
    assert any("Disk full" in r.message for r in caplog.records)


def test_enrichment_cache_enospc_warning_deduped(monkeypatch, caplog):
    """The low-disk warning is emitted once, not once per cache file."""
    monkeypatch.setattr(enrichment.tempfile, "mkstemp", _enospc)
    with caplog.at_level("WARNING"):
        enrichment._save_enrichment_cache()
    low_disk = [r for r in caplog.records if "Disk full" in r.message]
    assert len(low_disk) == 1  # two cache files (nvd + epss), one warning


def test_kev_cache_enospc_no_partial_file(monkeypatch):
    """A mid-write ENOSPC on the KEV cache leaves no half-written (corrupt) file."""
    monkeypatch.setattr(enrichment.tempfile, "mkstemp", _enospc)
    enrichment._persist_kev_cache({"CVE-2025-9": {"date_added": "2026-01-01"}})  # no raise
    assert not enrichment._KEV_CACHE_FILE.exists()


def test_kev_cache_atomic_write_succeeds(tmp_path):
    """Happy path: KEV cache is written atomically and is readable."""
    enrichment._persist_kev_cache({"CVE-2025-9": {"date_added": "2026-01-01"}})
    data = json.loads(enrichment._KEV_CACHE_FILE.read_text())
    assert data["data"]["CVE-2025-9"]["date_added"] == "2026-01-01"
    # no leftover temp files
    assert not list(tmp_path.glob("*.tmp"))


# ── AGENT_BOM_STATE_DIR coverage (site 3 of the brief) ─────────────────────────


def test_state_dir_redirects_enrichment_off_home(monkeypatch, tmp_path):
    """AGENT_BOM_STATE_DIR redirects the enrichment cache dir off $HOME."""
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "roomy"))
    assert enrichment._state_dir() == tmp_path / "roomy"
    assert "AGENT_BOM_STATE_DIR" in enrichment._state_dir.__doc__


def test_state_dir_defaults_to_home(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_STATE_DIR", raising=False)
    assert enrichment._state_dir() == Path.home() / ".agent-bom"


def test_update_check_stamp_honors_state_dir(monkeypatch, tmp_path):
    """The CLI update-check stamp lands under AGENT_BOM_STATE_DIR, not $HOME."""
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    target = cli_common._update_check_cache_file()
    assert target == tmp_path / "state" / "update-check.txt"


# ── update-check stamp write (site 2) ──────────────────────────────────────────


def test_update_check_enospc_does_not_crash(monkeypatch, tmp_path):
    """A full disk on the update-check stamp write must not crash the thread."""
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(cli_common, "_update_check_result", None, raising=False)
    cli_common._update_check_done.clear()

    import agent_bom.http_client as http_client

    monkeypatch.setattr(
        http_client,
        "fetch_json",
        lambda *_a, **_k: {"info": {"version": "999.0.0"}},
    )

    real_write_text = Path.write_text

    def _boom(self, *a, **k):
        if self.name == "update-check.txt":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write_text(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", _boom)

    cli_common._check_for_update_bg()  # must not raise
    # update notice still computed and served this run despite the failed cache write
    assert cli_common._update_check_result is not None
    assert "999.0.0" in cli_common._update_check_result


# ── report -o write (site: the final report) ───────────────────────────────────


def _make_ctx(report: AIBOMReport) -> ScanContext:
    from rich.console import Console

    return ScanContext(con=Console(stderr=True), report=report, blast_radii=[], exit_code=1)


def _report() -> AIBOMReport:
    return AIBOMReport(
        agents=[],
        blast_radii=[],
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        tool_version="0.0.0-test",
    )


def test_report_write_enospc_falls_back_to_stdout(monkeypatch, tmp_path, capsys):
    """A full disk on the -o JSON report write emits results to stdout, no traceback."""
    out = tmp_path / "report.json"

    import agent_bom.output.json_fmt as json_fmt

    monkeypatch.setattr(json_fmt.Path, "write_text", _enospc, raising=False)

    ctx = _make_ctx(_report())
    # Must NOT raise — the scan already did all the work.
    render_output(
        ctx,
        output=str(out),
        output_format="json",
        no_tree=True,
        quiet=False,
        no_color=True,
        open_report=False,
        compliance_export=None,
        mermaid_mode="supply-chain",
        push_gateway=None,
        otel_endpoint=None,
        baseline=None,
        delta_mode=False,
    )
    captured = capsys.readouterr()
    # JSON report serialized to stdout instead of the unwritable file
    payload = json.loads(captured.out)
    assert payload["ai_bom_version"] == "0.0.0-test"
    assert not out.exists()


def test_report_write_enospc_pdf_skips_cleanly(monkeypatch, tmp_path):
    """PDF has no stdout representation — skip with a clear message, never crash."""
    out = tmp_path / "report.pdf"

    import agent_bom.cli.agents._output as out_mod

    def _export_pdf_boom(*_a, **_k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(out_mod, "export_pdf", _export_pdf_boom)

    ctx = _make_ctx(_report())
    render_output(  # must not raise
        ctx,
        output=str(out),
        output_format="pdf",
        no_tree=True,
        quiet=False,
        no_color=True,
        open_report=False,
        compliance_export=None,
        mermaid_mode="supply-chain",
        push_gateway=None,
        otel_endpoint=None,
        baseline=None,
        delta_mode=False,
    )
    assert not out.exists()
