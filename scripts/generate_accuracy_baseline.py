#!/usr/bin/env python3
"""Generate or verify the checked-in scanner accuracy baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "accuracy-baseline.json"


def _payload() -> str:
    from agent_bom.accuracy_baseline import build_accuracy_baseline

    return json.dumps(build_accuracy_baseline(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if docs/accuracy-baseline.json is stale")
    args = parser.parse_args()

    expected = _payload()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != expected:
            sys.stderr.write(f"{OUTPUT.relative_to(ROOT)} is stale; run scripts/generate_accuracy_baseline.py\n")
            return 1
        return 0

    OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
