#!/usr/bin/env python3
"""CI gate: fail on cloud benchmark catalog / registry / classification drift.

Compares the committed control inventory (``benchmark_inventory.json``) against
the live code registries and pinned provenance. Fails on duplicate control IDs,
registry count/digest divergence, automated/manual classification divergence,
provenance changes, or any coverage percentage published without a
repository-provenanced denominator.

Run: python scripts/check_benchmark_drift.py
Exit 0 = in sync. Exit 1 = drift detected (regenerate benchmark_inventory.json).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_bom.cloud import benchmark_provenance as bp  # noqa: E402


def main() -> int:
    committed = bp.load_committed_inventory()
    live = bp.build_drift_records()
    problems = bp.evaluate_drift(committed, live)
    if problems:
        print("Benchmark inventory drift detected:")
        for problem in problems:
            print(f"  - {problem}")
        print("\nRegenerate with: python scripts/generate_benchmark_inventory.py")
        return 1
    print(f"Benchmark inventory in sync across {len(live)} providers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
