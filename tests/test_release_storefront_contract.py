"""Release storefront contracts for concise onboarding and sanitized proof."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_manifest_covers_dark_light_and_mobile_product_proof() -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    entries = {entry["path"]: entry for entry in manifest["screenshots"]}

    required = {
        "dashboard-live.png": "dark desktop",
        "dashboard-light-live.png": "light desktop",
        "dashboard-mobile-live.png": "dark mobile",
        "security-graph-live.png": "dark desktop",
        "security-graph-light-live.png": "light desktop",
        "security-graph-mobile-live.png": "dark mobile",
    }
    for path, presentation in required.items():
        assert path in entries
        assert entries[path]["presentation"] == presentation
        assert (ROOT / "docs/images" / path).is_file()

    note = str(manifest["capture_note"])
    assert "deterministic" in note.lower()
    assert "customer" in note.lower()
