"""Tests for the synthetic-estate scale generator (scripts/bench/generate_estate.py)."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bench" / "generate_estate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("generate_estate", _MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_estate"] = module
    spec.loader.exec_module(module)
    return module


ge = _load_module()


# ─── Determinism ─────────────────────────────────────────────────────────────


def test_same_seed_reproducible():
    a = ge.make_finding(42, 7, **ge.default_estate(5000))
    b = ge.make_finding(42, 7, **ge.default_estate(5000))
    assert a == b


def test_different_seed_differs():
    a = ge.make_finding(1, 7, **ge.default_estate(5000))
    b = ge.make_finding(2, 7, **ge.default_estate(5000))
    assert a != b


def test_no_wallclock_dependence():
    """Two runs separated in time must be identical (seeded, not clock-based)."""
    import time

    first = ge.make_finding(9, 3, **ge.default_estate(5000))
    time.sleep(0.01)
    second = ge.make_finding(9, 3, **ge.default_estate(5000))
    assert first == second


# ─── Distribution / realism ──────────────────────────────────────────────────


def test_ndjson_valid_jsonl_and_distributed(tmp_path):
    estate = ge.default_estate(5000)
    out = tmp_path / "estate.jsonl"
    rows, nbytes = ge.write_ndjson(ge.iter_findings(123, 5000, **estate), str(out))
    assert rows == 5000
    assert nbytes > 0

    lines = out.read_text().splitlines()
    assert len(lines) == 5000
    parsed = [json.loads(line) for line in lines]  # every line valid JSON
    for row in parsed:
        assert row["id"]
        assert row["cve_id"]
        assert row["evidence"]["ecosystem"] in ge._ECOSYSTEMS

    # NOT all-identical: multiple severities, ecosystems, cvss values, ids.
    severities = Counter(r["severity"] for r in parsed)
    assert len(severities) >= 3, severities
    assert len({r["evidence"]["ecosystem"] for r in parsed}) >= 5
    assert len({r["cvss_score"] for r in parsed}) > 20
    assert len({r["id"] for r in parsed}) == 5000  # unique ids

    # Weighted realism: low+medium dominate, critical is a minority.
    assert severities["low"] + severities["medium"] > severities["high"] + severities["critical"]
    assert severities["critical"] < severities["low"]

    # Both CVE and GHSA ids appear.
    prefixes = {r["cve_id"].split("-")[0] for r in parsed}
    assert "CVE" in prefixes and "GHSA" in prefixes

    # fixed_version is a present-or-null mix (exercises null-sort paths).
    fixed_present = sum(1 for r in parsed if r["fixed_version"])
    assert 0 < fixed_present < 5000

    # Reachability varies.
    assert len({r["reachability"] for r in parsed}) >= 3


def test_kev_and_epss_are_bounded():
    for idx in range(500):
        f = ge.make_finding(7, idx, **ge.default_estate(500))
        assert 0.0 <= f["epss_score"] <= 1.0
        assert 0.0 <= f["cvss_score"] <= 10.0
        assert isinstance(f["is_kev"], bool)


# ─── Sizing math ─────────────────────────────────────────────────────────────


def test_target_gb_sizing_roughly_right(tmp_path):
    # 0.01 GB target → a count; the written file should be within ~2x of target.
    target_gb = 0.01
    count = ge.findings_for_target_gb(target_gb)
    assert count > 0
    estate = ge.default_estate(count)
    out = tmp_path / "sized.jsonl"
    rows, nbytes = ge.write_ndjson(ge.iter_findings(5, count, **estate), str(out))
    assert rows == count
    target_bytes = target_gb * (1024**3)
    ratio = nbytes / target_bytes
    assert 0.5 <= ratio <= 2.0, f"sizing off: {ratio:.2f} ({nbytes} vs {target_bytes})"


def test_default_estate_scales_and_sane():
    est = ge.default_estate(1_000_000)
    assert est["agents"] < est["packages"]  # fewer agents than packages
    assert all(v >= 1 for v in est.values())
    small = ge.default_estate(1)
    assert all(v >= 1 for v in small.values())  # never zero → no modulo-by-zero


# ─── Streaming (no full buffering) ───────────────────────────────────────────


def test_iter_findings_is_lazy_generator():
    it = ge.iter_findings(1, 10_000_000, **ge.default_estate(10_000_000))
    assert isinstance(it, Iterator)
    # Pull two rows from a 10M-row stream instantly without materializing it.
    first = next(it)
    second = next(it)
    assert first["id"] != second["id"]


def test_write_ndjson_consumes_lazily(tmp_path):
    """The writer must pull from the generator, not receive a materialized list."""
    consumed = 0

    def gen() -> Iterator[dict]:
        nonlocal consumed
        for idx in range(2000):
            consumed += 1
            yield ge.make_finding(1, idx, **ge.default_estate(2000))

    out = tmp_path / "lazy.jsonl"
    ge.write_ndjson(gen(), str(out))
    assert consumed == 2000  # generator was driven to completion by the writer


def test_batches_stream_in_chunks():
    def gen() -> Iterator[dict]:
        for idx in range(2500):
            yield {"idx": idx}

    sizes = [len(b) for b in ge._iter_batches(gen(), 1000)]
    assert sizes == [1000, 1000, 500]


# ─── Parquet round-trip ──────────────────────────────────────────────────────


def test_parquet_roundtrip(tmp_path):
    pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    estate = ge.default_estate(3000)
    out = tmp_path / "estate.parquet"
    rows, nbytes = ge.write_parquet(ge.iter_findings(77, 3000, **estate), str(out), batch_size=500)
    assert rows == 3000
    assert nbytes > 0

    table = pq.read_table(str(out))
    assert table.num_rows == 3000
    assert table.column_names == ge._PARQUET_COLUMNS

    # Columns carry a distribution, not one repeated value.
    severities = set(table.column("severity").to_pylist())
    assert len(severities) >= 3
    ecosystems = set(table.column("ecosystem").to_pylist())
    assert len(ecosystems) >= 5
    # graph_reachable is a real bool column; some true, some false.
    reach = table.column("graph_reachable").to_pylist()
    assert any(reach) and not all(reach)


def test_parquet_schema_matches_agent_bom():
    """The generator's column list must equal agent-bom's canonical parquet schema."""
    pytest.importorskip("pyarrow")
    try:
        from agent_bom.output.parquet_fmt import _COLUMNS
    except Exception:
        pytest.skip("agent_bom not importable in this environment")
    assert ge._PARQUET_COLUMNS == list(_COLUMNS)


# ─── Idempotency key determinism (bulk mode) ─────────────────────────────────


def test_bulk_idempotency_key_deterministic():
    k1 = ge._batch_idempotency_key(1337, "estate-bench", 4)
    k2 = ge._batch_idempotency_key(1337, "estate-bench", 4)
    k3 = ge._batch_idempotency_key(1337, "estate-bench", 5)
    assert k1 == k2
    assert k1 != k3
    assert k1.startswith("estate-")


# ─── CLI wiring ──────────────────────────────────────────────────────────────


def test_cli_ndjson_end_to_end(tmp_path):
    out = tmp_path / "cli.jsonl"
    rc = ge.main(["--findings", "500", "--seed", "3", "--out", "ndjson", str(out)])
    assert rc == 0
    assert len(out.read_text().splitlines()) == 500


def test_cli_target_gb_and_findings_mutually_exclusive():
    with pytest.raises(SystemExit):
        ge.main(["--findings", "10", "--target-gb", "1", "--out", "ndjson", "-"])
