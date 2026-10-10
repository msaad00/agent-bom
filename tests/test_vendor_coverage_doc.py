"""The generated vendor-coverage matrix stays in sync with code and cites a source per cell."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_JSON = ROOT / "docs" / "VENDOR_COVERAGE.json"


def test_committed_vendor_coverage_matches_generator() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_vendor_coverage.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_every_cloud_matrix_cell_cites_a_source() -> None:
    data = json.loads(DOC_JSON.read_text(encoding="utf-8"))
    matrix = data["cloud_matrix"]
    lane_ids = {lane["id"] for lane in matrix["lanes"]}

    assert matrix["rows"], "matrix must list providers"
    for row in matrix["rows"]:
        assert set(row["cells"]) == lane_ids, row["provider"]
        for lane_id, cell in row["cells"].items():
            assert cell["source"]["path"], (row["provider"], lane_id)
            assert cell["source"]["symbol"], (row["provider"], lane_id)
            assert cell["display"], (row["provider"], lane_id)

    gaps = sum(1 for row in matrix["rows"] for cell in row["cells"].values() if cell["display"] == "—")
    assert gaps == matrix["gap_count"]


def test_every_integration_category_cites_a_source() -> None:
    data = json.loads(DOC_JSON.read_text(encoding="utf-8"))

    assert data["integrations"]
    for category in data["integrations"]:
        assert category["sources"], category["id"]
        for source in category["sources"]:
            assert source["path"] and source["symbol"], category["id"]
    for group in data["disagreements"]:
        assert group["providers_not_in_every_list"], group["id"]
        assert all(entry["source"]["path"] for entry in group["lists"]), group["id"]
