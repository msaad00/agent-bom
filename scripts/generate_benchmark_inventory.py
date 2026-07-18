#!/usr/bin/env python3
"""Regenerate the committed cloud benchmark control inventory.

The inventory is derived from the code registries + pinned provenance in
``agent_bom.cloud.benchmark_provenance``. Run this after adding, removing, or
reclassifying a benchmark check; ``scripts/check_benchmark_drift.py`` fails CI
if the committed artifact is stale.

Run: python scripts/generate_benchmark_inventory.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_bom.cloud import benchmark_provenance as bp  # noqa: E402


def main() -> int:
    rendered = bp.render_committed_inventory()
    bp.INVENTORY_PATH.write_text(rendered)
    print(f"Wrote {bp.INVENTORY_PATH.relative_to(Path(__file__).resolve().parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
