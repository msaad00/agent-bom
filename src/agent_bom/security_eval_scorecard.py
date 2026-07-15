"""Security-eval scorecard — package a red-team run as a structured eval artifact.

Turns a ``red_team`` run into a schema-versioned "security-eval scorecard" that
can sit alongside quality/accuracy evals: catalog coverage %, false-positive
rate, and per-category pass/fail. Deterministic and offline (no LLM, no clock,
no randomness) so it is safe to emit inside release gates and to diff.

The three required facets:

* **coverage %** — how much of the curated attack catalog this run exercised
  (``attacks_run / catalog_size``). A partial run scores below 100 %.
* **false-positive rate** — benign cases that tripped a detector.
* **per-category pass/fail** — detection outcome broken out by attack category.
"""

from __future__ import annotations

from typing import Any

from agent_bom.red_team import _ATTACKS, RedTeamResult, build_report, run_attacks

SCHEMA_VERSION = "security-eval-scorecard/v1"

CATALOG_SIZE = len(_ATTACKS)


def build_security_eval_scorecard(results: list[RedTeamResult] | None = None) -> dict[str, Any]:
    """Build the security-eval scorecard artifact.

    Args:
        results: Optional pre-computed per-attack results (e.g. from a partial
            run or the LLM-harnessed variant). When ``None`` the full curated
            catalog is run through Shield.

    Returns:
        A deterministic, JSON-serializable scorecard dict.
    """
    if results is None:
        results = run_attacks(_ATTACKS)

    report = build_report(results)
    attacks_run = report["total"]
    coverage_pct = round(attacks_run / CATALOG_SIZE * 100, 1) if CATALOG_SIZE else 0.0

    per_category: dict[str, dict[str, Any]] = {}
    for category, stats in report["by_category"].items():
        total = int(stats["total"])
        passed = int(stats["passed"])
        failed = total - passed
        per_category[category] = {
            "total": total,
            "detected": int(stats["detected"]),
            "passed": passed,
            "failed": failed,
            "pass": failed == 0,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "eval_type": "security",
        "eval_name": "red-team-adversarial-coverage",
        "catalog_size": CATALOG_SIZE,
        "attacks_run": attacks_run,
        "coverage_pct": coverage_pct,
        "attack_cases": report["attacks"],
        "benign_cases": report["benign"],
        "detected": report["detected"],
        "missed": report["missed"],
        "detection_rate": report["detection_rate"],
        "false_positives": report["false_positives"],
        "false_positive_rate": report["false_positive_rate"],
        "per_category": per_category,
        # A scorecard passes only with zero missed attacks and zero false positives.
        "passed": report["missed"] == 0 and report["false_positives"] == 0,
    }
