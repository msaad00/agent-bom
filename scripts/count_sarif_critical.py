#!/usr/bin/env python3
"""Count critical SARIF results for release self-scan gates.

agent-bom maps both ``critical`` and ``high`` findings to SARIF ``level=error``.
Release gates that use ``--fail-on-severity critical`` must therefore count by
``security-severity`` (>= 9.0), not by raw result count or ``level==error``.

Usage:
    python scripts/count_sarif_critical.py path/to/file.sarif
    # prints an integer count on stdout; exits 2 on unreadable input
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _security_severity(result: dict[str, Any], rules_by_id: dict[str, dict[str, Any]]) -> float | None:
    props = result.get("properties") or {}
    raw = props.get("security-severity")
    if raw is None:
        rule = rules_by_id.get(str(result.get("ruleId") or ""))
        if rule is not None:
            raw = (rule.get("properties") or {}).get("security-severity")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def count_critical_results(sarif: dict[str, Any]) -> int:
    """Return the number of SARIF results at critical severity (score >= 9.0)."""
    total = 0
    for run in sarif.get("runs") or []:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        rules_by_id = {str(rule.get("id") or ""): rule for rule in rules if isinstance(rule, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            score = _security_severity(result, rules_by_id)
            if score is not None and score >= 9.0:
                total += 1
    return total


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: count_sarif_critical.py <file.sarif>", file=sys.stderr)
        return 2
    path = Path(args[0])
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unreadable SARIF: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print("unreadable SARIF: root must be an object", file=sys.stderr)
        return 2
    print(count_critical_results(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
