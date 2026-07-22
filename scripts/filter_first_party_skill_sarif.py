"""Remove non-actionable medium/low skill findings from first-party instructions."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_FIRST_PARTY_PREFIXES = (".cursor/rules/", ".agents/")
_FIRST_PARTY_FILES = {"AGENTS.md", "CLAUDE.md"}


def _is_first_party_instruction(uri: object) -> bool:
    if not isinstance(uri, str):
        return False
    normalized = uri.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized in _FIRST_PARTY_FILES or normalized.startswith(_FIRST_PARTY_PREFIXES)


def _severity_score(result: dict[str, Any], rules: dict[str, dict[str, Any]]) -> float:
    props = result.get("properties") or {}
    raw = props.get("security-severity")
    if raw is None:
        raw = (rules.get(str(result.get("ruleId") or "")) or {}).get("properties", {}).get("security-severity")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def filter_sarif(data: dict[str, Any]) -> int:
    """Filter first-party informational skill rows and return removal count."""
    removed = 0
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {
            str(rule.get("id") or ""): rule
            for rule in driver.get("rules", [])
            if isinstance(rule, dict)
        }
        kept: list[dict[str, Any]] = []
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            locations = result.get("locations") or []
            uri = None
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                uri = artifact.get("uri")
            informational_skill = (
                str(result.get("ruleId") or "").startswith("finding/SKILL")
                and _severity_score(result, rules) < 7.0
                and _is_first_party_instruction(uri)
            )
            if informational_skill:
                removed += 1
            else:
                kept.append(result)
        run["results"] = kept
    return removed


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} SARIF_PATH", file=sys.stderr)
        return 64
    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))
    removed = filter_sarif(data)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Filtered {removed} first-party informational skill finding(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
