#!/usr/bin/env python3
"""Generate or verify the architecture compliance coverage table."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "ARCHITECTURE.md"
START = "<!-- compliance-coverage:start -->"
END = "<!-- compliance-coverage:end -->"

sys.path.insert(0, str(ROOT / "src"))

from agent_bom.compliance_coverage import render_compliance_coverage_table  # noqa: E402


def _expected_doc(current: str) -> str:
    start_idx = current.index(START)
    end_idx = current.index(END, start_idx)
    generated = START + "\n" + render_compliance_coverage_table() + "\n" + END
    return current[:start_idx] + generated + current[end_idx + len(END) :]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if docs/ARCHITECTURE.md coverage table has drifted")
    args = parser.parse_args()

    current = DOC.read_text(encoding="utf-8")
    try:
        expected = _expected_doc(current)
    except ValueError as exc:
        raise SystemExit(f"{DOC.relative_to(ROOT)} is missing compliance coverage markers") from exc

    if args.check:
        if current != expected:
            print(
                "docs/ARCHITECTURE.md compliance coverage table is stale; run `python scripts/generate_compliance_coverage_table.py`.",
                file=sys.stderr,
            )
            return 1
        return 0

    DOC.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
